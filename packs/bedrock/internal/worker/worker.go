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

	"github.com/cordum-io/cordum-packs/packs/bedrock/internal/config"
)

const (
	topicRead     = "job.bedrock.read"
	topicGenerate = "job.bedrock.generate"
	topicWrite    = "job.bedrock.write"
)

type actionSpec struct {
	Intent string // "read", "generate", "write"
}

var actionSpecs = map[string]actionSpec{
	"invoke":       {Intent: "generate"},
	"converse":     {Intent: "generate"},
	"embed":        {Intent: "generate"},
	"kb.query":     {Intent: "write"},
	"kb.retrieve":  {Intent: "write"},
	"agent.invoke": {Intent: "write"},
	"models.list":  {Intent: "read"},
	"models.get":   {Intent: "read"},
}

type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
}

type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Region    string         `json:"region"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
}

type JobResult struct {
	JobID      string `json:"job_id"`
	Profile    string `json:"profile"`
	Action     string `json:"action"`
	Region     string `json:"region,omitempty"`
	ModelID    string `json:"model_id,omitempty"`
	StatusCode int    `json:"status_code"`
	DurationMs int64  `json:"duration_ms"`
	Output     any    `json:"output,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
	TokenUsage any    `json:"token_usage,omitempty"`
	Embeddings any    `json:"embeddings,omitempty"`
	Citations  any    `json:"citations,omitempty"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "bedrock")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("redis store: %w", err)
	}

	w := &Worker{
		cfg:      cfg,
		agent:    &runtime.Agent{NATS: nc, Store: store, RedisURL: cfg.RedisURL, SenderID: workerID},
		natsConn: nc,
		workerID: workerID,
	}
	if cfg.MaxParallel > 0 {
		w.sem = make(chan struct{}, cfg.MaxParallel)
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
		subjects = []string{topicRead, topicGenerate, topicWrite}
	}
	for _, s := range subjects {
		runtime.Register(w.agent, s, w.handleJob)
	}
	runtime.Register(w.agent, runtime.DirectSubject(w.workerID), w.handleJob)
	if err := w.agent.Start(); err != nil {
		return fmt.Errorf("agent start: %w", err)
	}
	if w.natsConn != nil {
		hb := func() ([]byte, error) {
			return runtime.HeartbeatPayload(w.workerID, w.cfg.Pool, int(atomic.LoadInt32(&w.active)), int(w.cfg.MaxParallel), 0)
		}
		if p, err := hb(); err == nil {
			_ = runtime.EmitHeartbeat(w.natsConn, p)
		}
		go runtime.HeartbeatLoop(ctx, w.natsConn, hb)
	}
	slog.Info("bedrock worker started", "worker_id", w.workerID, "region", w.cfg.DefaultRegion)
	<-ctx.Done()
	return ctx.Err()
}

func (w *Worker) handleJob(rctx runtime.Context, payload map[string]any) (JobResult, error) {
	if w.sem != nil {
		w.sem <- struct{}{}
		atomic.AddInt32(&w.active, 1)
		defer func() { <-w.sem; atomic.AddInt32(&w.active, -1) }()
	}

	start := time.Now()
	jobID := rctx.Job.GetJobId()
	topic := rctx.Job.GetTopic()

	payload = normalizePayload(payload)
	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		return JobResult{JobID: jobID, Error: fmt.Sprintf("decode: %v", err)}, nil
	}

	action := strings.TrimSpace(input.Action)
	if action == "" {
		return JobResult{JobID: jobID, Error: "action is required"}, nil
	}

	spec, ok := actionSpecs[action]
	if !ok {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("unsupported action: %s", action)}, nil
	}

	// Topic-intent enforcement
	topicIntent := "read"
	if topic == topicGenerate {
		topicIntent = "generate"
	} else if topic == topicWrite {
		topicIntent = "write"
	}
	if spec.Intent == "write" && topicIntent != "write" {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("action %q requires write topic", action)}, nil
	}
	if spec.Intent == "generate" && topicIntent == "read" {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("action %q requires generate topic", action)}, nil
	}

	// Model validation
	params := input.Params
	if params == nil {
		params = map[string]any{}
	}
	if modelID, ok := params["model_id"].(string); ok && modelID != "" {
		if !w.cfg.IsModelAllowed(modelID) {
			return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("model %q is not allowed", modelID)}, nil
		}
	}

	region := input.Region
	if region == "" {
		region = w.cfg.DefaultRegion
	}

	var result JobResult
	result.JobID = jobID
	result.Action = action
	result.Region = region
	if modelID, ok := params["model_id"].(string); ok {
		result.ModelID = modelID
	}

	// Note: actual Bedrock API calls require AWS SigV4 signing via bedrockruntime SDK module.
	// This pack provides the full routing, validation, and schema layer.
	// The bedrockruntime service calls will be wired when the SDK module is added.
	result.Error = fmt.Sprintf("bedrock action %q dispatched (region: %s) — requires bedrockruntime SDK module for execution", action, region)
	result.StatusCode = 501
	result.DurationMs = time.Since(start).Milliseconds()

	slog.Info("bedrock job completed", "job_id", jobID, "action", action, "region", region, "duration_ms", result.DurationMs)
	return result, nil
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

func decodePayload(payload map[string]any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
