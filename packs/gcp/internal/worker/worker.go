package worker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/config"
	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

// Worker handles GCP pack jobs.
type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
}

// JobInput is the incoming job payload.
type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	ProjectID string         `json:"project_id"`
	Location  string         `json:"location"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
}

// JobResult is the output payload.
type JobResult struct {
	JobID      string `json:"job_id"`
	Profile    string `json:"profile"`
	Action     string `json:"action"`
	ProjectID  string `json:"project_id,omitempty"`
	Location   string `json:"location,omitempty"`
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

// New creates a new GCP worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "gcp")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("redis store: %w", err)
	}

	runtimeAgent := &runtime.Agent{
		NATS:     nc,
		Store:    store,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	w := &Worker{
		cfg:      cfg,
		agent:    runtimeAgent,
		natsConn: nc,
		workerID: workerID,
	}
	if cfg.MaxParallel > 0 {
		w.sem = make(chan struct{}, cfg.MaxParallel)
	}
	return w, nil
}

// Close shuts down the worker.
func (w *Worker) Close() error {
	if w.agent != nil {
		_ = w.agent.Close()
	}
	return nil
}

// Run starts the worker and blocks until ctx is done.
func (w *Worker) Run(ctx context.Context) error {
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}

	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{topicRead, topicWrite}
	}
	for _, subject := range subjects {
		runtime.Register(w.agent, subject, w.handleJob)
	}
	runtime.Register(w.agent, runtime.DirectSubject(w.workerID), w.handleJob)

	if err := w.agent.Start(); err != nil {
		return fmt.Errorf("agent start: %w", err)
	}

	if w.natsConn != nil {
		heartbeatFn := func() ([]byte, error) {
			active := int(atomic.LoadInt32(&w.active))
			return runtime.HeartbeatPayload(w.workerID, w.cfg.Pool, active, int(w.cfg.MaxParallel), 0)
		}
		if payload, err := heartbeatFn(); err == nil {
			_ = runtime.EmitHeartbeat(w.natsConn, payload)
		}
		go runtime.HeartbeatLoop(ctx, w.natsConn, heartbeatFn)
	}

	slog.Info("gcp worker started", "worker_id", w.workerID, "subjects", subjects)

	<-ctx.Done()
	return ctx.Err()
}

func (w *Worker) handleJob(rctx runtime.Context, payload map[string]any) (JobResult, error) {
	if w.sem != nil {
		w.sem <- struct{}{}
		atomic.AddInt32(&w.active, 1)
		defer func() {
			<-w.sem
			atomic.AddInt32(&w.active, -1)
		}()
	}

	start := time.Now()
	jobID := rctx.Job.GetJobId()
	topic := rctx.Job.GetTopic()

	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.RequestTimeout)
	defer cancel()

	payload = normalizePayload(payload)

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		return JobResult{JobID: jobID, Error: fmt.Sprintf("decode input: %v", err)}, nil
	}

	action := strings.TrimSpace(input.Action)
	if action == "" {
		return JobResult{JobID: jobID, RequestID: input.RequestID, Error: "action is required"}, nil
	}

	spec, ok := actionSpecs[action]
	if !ok {
		return JobResult{JobID: jobID, Action: action, RequestID: input.RequestID, Error: fmt.Sprintf("unsupported action: %s", action)}, nil
	}

	if spec.Intent == "write" && topic != topicWrite {
		return JobResult{
			JobID:     jobID,
			Action:    action,
			RequestID: input.RequestID,
			Error:     fmt.Sprintf("action %q requires write topic (%s) but was sent to %s", action, topicWrite, topic),
		}, nil
	}

	profile := w.cfg.ResolveProfile(input.Profile)
	if !profile.IsActionAllowed(action) {
		return JobResult{
			JobID:     jobID,
			Profile:   profile.Name,
			Action:    action,
			RequestID: input.RequestID,
			Error:     fmt.Sprintf("action %q is not allowed by profile %q", action, profile.Name),
		}, nil
	}

	reqCfg, err := gcpclient.ResolveRequestConfig(ctx, w.cfg, profile.Name, input.ProjectID, input.Location)
	if err != nil {
		return JobResult{
			JobID:     jobID,
			Profile:   profile.Name,
			Action:    action,
			ProjectID: strings.TrimSpace(input.ProjectID),
			Location:  strings.TrimSpace(input.Location),
			RequestID: input.RequestID,
			Error:     fmt.Sprintf("gcp config: %v", err),
		}, nil
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	result, err := dispatchAction(ctx, reqCfg, action, spec, params)

	jobResult := JobResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     action,
		ProjectID:  reqCfg.ProjectID,
		Location:   reqCfg.Location,
		RequestID:  input.RequestID,
		DurationMs: time.Since(start).Milliseconds(),
	}
	if err != nil {
		jobResult.Error = err.Error()
	} else {
		jobResult.Result = result
		jobResult.StatusCode = 200
	}

	slog.Info("gcp job completed",
		"job_id", jobID,
		"action", action,
		"service", spec.Service,
		"project_id", jobResult.ProjectID,
		"location", jobResult.Location,
		"duration_ms", jobResult.DurationMs,
		"error", jobResult.Error,
	)

	return jobResult, nil
}
