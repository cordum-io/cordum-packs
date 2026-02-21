package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/pic-standard/internal/config"
	"github.com/cordum-io/cordum-packs/packs/pic-standard/internal/picclient"
	"github.com/cordum-io/cordum-packs/packs/pic-standard/internal/policy"
)

const topicVerify = "job.pic-standard.verify"

// PicVerifyInput matches pack/schemas/PicVerifyInput.json.
type PicVerifyInput struct {
	ToolName string         `json:"tool_name"`
	ToolArgs map[string]any `json:"tool_args,omitempty"`
}

type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	pic      *picclient.Client
	sem      chan struct{}
	active   int32
	log      *slog.Logger
}

func New(cfg config.Config, logger *slog.Logger) (*Worker, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.GatewayURL == "" {
		return nil, fmt.Errorf("gateway url required")
	}
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "pic-standard")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("redis blob store: %w", err)
	}

	agent := &runtime.Agent{
		NATS:     nc,
		Store:    store,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	pic := picclient.New(cfg.BridgeURL, cfg.BridgeTimeout)

	w := &Worker{
		cfg:      cfg,
		agent:    agent,
		natsConn: nc,
		workerID: workerID,
		pic:      pic,
		log:      logger,
	}
	if cfg.MaxParallel > 0 {
		w.sem = make(chan struct{}, int(cfg.MaxParallel))
	}
	return w, nil
}

func (w *Worker) Close() error {
	if w.agent != nil {
		_ = w.agent.Close()
	}
	return nil
}

func (w *Worker) Run(ctx context.Context) error {
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}

	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{topicVerify}
	}
	for _, subject := range subjects {
		runtime.Register(w.agent, subject, w.handleJob)
	}
	runtime.Register(w.agent, runtime.DirectSubject(w.workerID), w.handleJob)

	if err := w.agent.Start(); err != nil {
		return err
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

	w.log.Info("worker started",
		"worker_id", w.workerID,
		"pool", w.cfg.Pool,
		"subjects", subjects,
		"bridge_url", w.cfg.BridgeURL,
	)

	<-ctx.Done()
	return ctx.Err()
}

func (w *Worker) handleJob(ctx runtime.Context, payload map[string]any) (policy.Output, error) {
	atomic.AddInt32(&w.active, 1)
	defer atomic.AddInt32(&w.active, -1)

	if w.sem != nil {
		w.sem <- struct{}{}
		defer func() { <-w.sem }()
	}

	jobID := ctx.Job.GetJobId()

	payload = normalizePayload(payload)
	var input PicVerifyInput
	if err := decodePayload(payload, &input); err != nil {
		w.log.Error("decode payload failed", "job_id", jobID, "error", err)
		return failOut("invalid payload"), nil
	}

	if strings.TrimSpace(input.ToolName) == "" {
		w.log.Warn("empty tool_name", "job_id", jobID)
		return failOut("tool_name required"), nil
	}

	// Call PIC bridge (fail-closed: never returns error)
	bridgeResp := w.pic.VerifyToolCall(context.Background(), input.ToolName, input.ToolArgs)

	w.log.Info("pic verify",
		"job_id", jobID,
		"tool_name", input.ToolName,
		"allowed", bridgeResp.Allowed,
		"eval_ms", bridgeResp.EvalMs,
	)

	// Extract impact from bridge error details if available
	var impact string
	if bridgeResp.Error != nil && bridgeResp.Error.Details != nil {
		if v, ok := bridgeResp.Error.Details["impact"].(string); ok {
			impact = v
		}
	}

	// Map to Cordum workflow output
	if impact != "" {
		return policy.MapResultWithImpact(bridgeResp, impact, w.cfg.RequireApprovalImpacts), nil
	}
	return policy.MapResult(bridgeResp), nil
}

// failOut returns a structured fail output for invalid input cases.
// This keeps the workflow deterministic (output.next is always available).
func failOut(reason string) policy.Output {
	return policy.Output{
		Allowed: false,
		EvalMs:  0,
		Next:    "fail",
		Impact:  nil,
		Reason:  reason,
	}
}

func decodePayload(payload map[string]any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func normalizePayload(payload map[string]any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	if ctxPayload, ok := payload["context"].(map[string]any); ok {
		return ctxPayload
	}
	return payload
}
