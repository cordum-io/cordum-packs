package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	capsdk "github.com/cordum-io/cap/v2/sdk/go"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultNATSURL        = "nats://127.0.0.1:4222"
	defaultConnectTimeout = 5 * time.Second
	defaultMaxParallel    = int32(1)
)

// Config controls worker behavior for legacy runtimes.
type Config struct {
	Pool            string
	Subjects        []string
	Queue           string
	NatsURL         string
	MaxParallelJobs int32
	Capabilities    []string
	Labels          map[string]string
	Type            string
	WorkerID        string
	HeartbeatEvery  time.Duration
	PublicKeys      map[string]*ecdsa.PublicKey
	PrivateKey      *ecdsa.PrivateKey
	// NATSTLSConfig overrides environment-derived TLS settings for the NATS
	// connection. When nil, NewWorker resolves TLS from NATS_TLS_* / CORDUM_TLS_*.
	NATSTLSConfig *tls.Config
}

// Worker subscribes to subjects and publishes job results.
type Worker struct {
	cfg      Config
	conn     *nats.Conn
	subjects []string
	queue    string
	workerID string
	pool     string

	sem    chan struct{}
	active int32

	subs []*nats.Subscription

	cancelMu sync.Mutex
	cancel   context.CancelFunc
	logger   *slog.Logger
}

// Option configures a Worker.
type Option func(*Worker)

// WithLogger sets the structured logger for the worker. If not provided,
// slog.Default() is used.
func WithLogger(l *slog.Logger) Option {
	return func(w *Worker) {
		if l != nil {
			w.logger = l
		}
	}
}

// NewWorker builds a worker with a NATS connection.
func NewWorker(cfg Config, opts ...Option) (*Worker, error) {
	subjects := trimSubjects(cfg.Subjects)
	if len(subjects) == 0 {
		if strings.TrimSpace(cfg.Type) == "" {
			return nil, errors.New("subjects required")
		}
		subjects = []string{fmt.Sprintf("job.%s.*", strings.TrimSpace(cfg.Type))}
	}

	workerID := resolveWorkerID(cfg.WorkerID, cfg.Type)
	pool := strings.TrimSpace(cfg.Pool)
	if pool == "" {
		pool = strings.TrimSpace(cfg.Type)
	}

	natsURL := strings.TrimSpace(cfg.NatsURL)
	if natsURL == "" {
		natsURL = strings.TrimSpace(os.Getenv("NATS_URL"))
	}
	if natsURL == "" {
		natsURL = defaultNATSURL
	}

	connectTimeout := defaultConnectTimeout
	natsOpts := []nats.Option{nats.Name(workerID), nats.Timeout(connectTimeout)}

	tlsCfg := cfg.NATSTLSConfig
	if tlsCfg == nil {
		var tlsErr error
		tlsCfg, tlsErr = NATSTLSConfigFromEnv()
		if tlsErr != nil {
			return nil, fmt.Errorf("nats tls config: %w", tlsErr)
		}
	}
	if tlsCfg != nil {
		natsOpts = append(natsOpts, nats.Secure(tlsCfg))
	}

	conn, err := nats.Connect(natsURL, natsOpts...)
	if err != nil {
		return nil, err
	}

	maxParallel := cfg.MaxParallelJobs
	if maxParallel <= 0 {
		maxParallel = defaultMaxParallel
	}

	w := &Worker{
		cfg:      cfg,
		conn:     conn,
		subjects: subjects,
		queue:    strings.TrimSpace(cfg.Queue),
		workerID: workerID,
		pool:     pool,
	}
	for _, opt := range opts {
		opt(w)
	}
	if w.logger == nil {
		w.logger = slog.Default()
	}
	if maxParallel > 0 {
		w.sem = make(chan struct{}, maxParallel)
	}
	// keep the resolved max parallel for heartbeat publishing
	w.cfg.MaxParallelJobs = maxParallel

	return w, nil
}

// Run subscribes to configured subjects and processes jobs until ctx is canceled.
func (w *Worker) Run(ctx context.Context, handler func(context.Context, *agentv1.JobRequest) (*agentv1.JobResult, error)) error {
	if handler == nil {
		return errors.New("handler required")
	}
	if w.conn == nil {
		return errors.New("nats connection unavailable")
	}

	subjects := w.subjectsWithDirect()
	for _, subject := range subjects {
		queue := w.queue
		if queue == "" {
			queue = subject
		}
		sub, err := w.conn.QueueSubscribe(subject, queue, func(msg *nats.Msg) {
			w.dispatch(ctx, msg, handler)
		})
		if err != nil {
			return fmt.Errorf("subscribe %s: %w", subject, err)
		}
		w.subsAppend(sub)
	}

	w.startHeartbeat(ctx)

	<-ctx.Done()
	return ctx.Err()
}

// Close drains the NATS connection.
func (w *Worker) Close() error {
	w.cancelMu.Lock()
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
	w.cancelMu.Unlock()

	if w.conn != nil {
		return w.conn.Drain()
	}
	return nil
}

func (w *Worker) dispatch(ctx context.Context, msg *nats.Msg, handler func(context.Context, *agentv1.JobRequest) (*agentv1.JobResult, error)) {
	if ctx.Err() != nil {
		return
	}
	if w.sem != nil {
		// Acquire a slot or bail out when the run context ends: a canceled
		// worker must not keep the NATS callback blocked on a full semaphore
		// (that wedges Close's Drain and stalls the subscription).
		select {
		case w.sem <- struct{}{}:
			atomic.AddInt32(&w.active, 1)
		case <-ctx.Done():
			return
		}
		// Defense in depth: do not START new work once shutdown has begun.
		// A handler that is already running keeps running and still publishes
		// its result (Drain flushes pending publishes); cancellation only
		// refuses new work.
		if ctx.Err() != nil {
			<-w.sem
			atomic.AddInt32(&w.active, -1)
			return
		}
	}

	go func() {
		defer func() {
			if w.sem != nil {
				<-w.sem
				atomic.AddInt32(&w.active, -1)
			}
		}()

		var packet agentv1.BusPacket
		if err := proto.Unmarshal(msg.Data, &packet); err != nil {
			w.logger.Error("decode packet failed", "error", err)
			return
		}
		if w.cfg.PublicKeys != nil {
			pub, ok := w.cfg.PublicKeys[packet.GetSenderId()]
			if !ok {
				w.logger.Error("no public key for sender", "senderId", packet.GetSenderId())
				return
			}
			if len(packet.GetSignature()) == 0 {
				w.logger.Error("missing signature", "senderId", packet.GetSenderId())
				return
			}
			if err := capsdk.VerifyPacketSignature(&packet, pub); err != nil {
				w.logger.Error("invalid signature", "senderId", packet.GetSenderId(), "error", err)
				return
			}
		}

		req := packet.GetJobRequest()
		if req == nil || req.GetJobId() == "" {
			return
		}

		jobLogger := w.logger.With("jobId", req.GetJobId(), "traceId", packet.GetTraceId())
		jobLogger.Debug("job received", "topic", req.GetTopic())

		start := time.Now()
		res, err := handler(ctx, req)
		execMs := time.Since(start).Milliseconds()

		if res == nil {
			res = &agentv1.JobResult{
				JobId:        req.GetJobId(),
				Status:       agentv1.JobStatus_JOB_STATUS_FAILED,
				ErrorMessage: "handler returned nil",
			}
		}
		if err != nil {
			if res.Status == agentv1.JobStatus_JOB_STATUS_UNSPECIFIED {
				res.Status = agentv1.JobStatus_JOB_STATUS_FAILED
			}
			if strings.TrimSpace(res.ErrorMessage) == "" {
				res.ErrorMessage = err.Error()
			}
		}
		if res.JobId == "" {
			res.JobId = req.GetJobId()
		}
		if res.WorkerId == "" {
			res.WorkerId = w.workerID
		}
		if res.ExecutionMs == 0 {
			res.ExecutionMs = execMs
		}

		out := &agentv1.BusPacket{
			TraceId:         packet.GetTraceId(),
			SenderId:        w.workerID,
			ProtocolVersion: capsdk.DefaultProtocolVersion,
			CreatedAt:       timestamppb.Now(),
			Payload: &agentv1.BusPacket_JobResult{
				JobResult: res,
			},
		}
		if w.cfg.PrivateKey != nil {
			if err := capsdk.SignPacket(out, w.cfg.PrivateKey); err != nil {
				jobLogger.Error("sign result failed", "error", err)
				return
			}
		}
		data, mErr := capsdk.MarshalDeterministic(out)
		if mErr != nil {
			jobLogger.Error("marshal result failed", "error", mErr)
			return
		}
		if err := w.conn.Publish(capsdk.SubjectResult, data); err != nil {
			jobLogger.Error("publish result failed", "error", err)
		} else {
			jobLogger.Debug("job completed", "status", res.Status.String(), "durationMs", execMs)
		}
	}()
}

func (w *Worker) startHeartbeat(ctx context.Context) {
	interval := w.cfg.HeartbeatEvery
	if interval <= 0 {
		interval = capsdk.DefaultHeartbeatInterval
	}
	hbCtx, cancel := context.WithCancel(ctx)
	w.cancelMu.Lock()
	w.cancel = cancel
	w.cancelMu.Unlock()

	payloadFn := func() ([]byte, error) {
		active := atomic.LoadInt32(&w.active)
		packet := &agentv1.BusPacket{
			SenderId:        w.workerID,
			ProtocolVersion: capsdk.DefaultProtocolVersion,
			CreatedAt:       timestamppb.Now(),
			Payload: &agentv1.BusPacket_Heartbeat{
				Heartbeat: &agentv1.Heartbeat{
					WorkerId:        w.workerID,
					Pool:            w.pool,
					Type:            w.cfg.Type,
					ActiveJobs:      active,
					MaxParallelJobs: w.cfg.MaxParallelJobs,
					Capabilities:    w.cfg.Capabilities,
					Labels:          w.cfg.Labels,
				},
			},
		}
		if w.cfg.PrivateKey != nil {
			if err := capsdk.SignPacket(packet, w.cfg.PrivateKey); err != nil {
				return nil, err
			}
		}
		return capsdk.MarshalDeterministic(packet)
	}

	if payload, err := payloadFn(); err == nil {
		_ = w.conn.Publish(capsdk.SubjectHeartbeat, payload)
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-ticker.C:
				payload, err := payloadFn()
				if err == nil {
					_ = w.conn.Publish(capsdk.SubjectHeartbeat, payload)
				}
			}
		}
	}()
}

func (w *Worker) subjectsWithDirect() []string {
	subjects := append([]string{}, w.subjects...)
	direct := DirectSubject(w.workerID)
	if direct == "" {
		return subjects
	}
	for _, subject := range subjects {
		if subject == direct {
			return subjects
		}
	}
	return append(subjects, direct)
}

func (w *Worker) subsAppend(sub *nats.Subscription) {
	if sub == nil {
		return
	}
	w.subs = append(w.subs, sub)
}

func trimSubjects(subjects []string) []string {
	if len(subjects) == 0 {
		return nil
	}
	out := make([]string, 0, len(subjects))
	seen := map[string]struct{}{}
	for _, subject := range subjects {
		if s := strings.TrimSpace(subject); s != "" {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func resolveWorkerID(explicit, workerType string) string {
	workerID := strings.TrimSpace(explicit)
	if workerID == "" {
		workerID = strings.TrimSpace(os.Getenv("WORKER_ID"))
	}
	if workerID != "" {
		return workerID
	}

	workerType = strings.TrimSpace(workerType)
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		if workerType != "" {
			return workerType
		}
		return "cordum-worker"
	}
	if workerType == "" {
		return host
	}
	return workerType + "-" + host
}
