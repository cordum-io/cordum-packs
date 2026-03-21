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

	"github.com/cordum-io/cordum-packs/packs/cohere/internal/cohereapi"
	"github.com/cordum-io/cordum-packs/packs/cohere/internal/config"
)

const (
	topicChat     = "job.cohere.chat"
	topicGenerate = "job.cohere.generate"
	topicEmbed    = "job.cohere.embed"
	topicRerank   = "job.cohere.rerank"
	topicClassify = "job.cohere.classify"
)

// Worker handles Cohere pack jobs.
type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
	client   *cohereapi.Client
}

// JobInput is the incoming job payload.
type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
}

// JobResult is the output payload.
type JobResult struct {
	JobID        string                `json:"job_id"`
	Profile      string                `json:"profile"`
	Action       string                `json:"action"`
	StatusCode   int                   `json:"status_code"`
	RequestID    string                `json:"request_id,omitempty"`
	DurationMs   int64                 `json:"duration_ms"`
	Model        string                `json:"model,omitempty"`
	Text         string                `json:"text,omitempty"`
	FinishReason string                `json:"finish_reason,omitempty"`
	Citations    any                   `json:"citations,omitempty"`
	ToolCalls    any                   `json:"tool_calls,omitempty"`
	BilledUnits  *cohereapi.BilledUnits `json:"billed_units,omitempty"`
	Embeddings   any                   `json:"embeddings,omitempty"`
	Results      any                   `json:"results,omitempty"`
	Result       any                   `json:"result,omitempty"`
	Error        string                `json:"error,omitempty"`
}

// New creates a new Cohere worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("COHERE_API_KEY is required")
	}

	workerID := resolveWorkerID("", "cohere")
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
		client:   cohereapi.NewClient(cfg.BaseURL, cfg.APIKey),
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
		subjects = []string{topicChat, topicGenerate, topicEmbed, topicRerank, topicClassify}
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
	slog.Info("cohere worker started", "worker_id", w.workerID, "subjects", subjects)
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
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.RequestTimeout)
	defer cancel()

	payload = normalizePayload(payload)
	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		return JobResult{JobID: jobID, Error: fmt.Sprintf("decode: %v", err)}, nil
	}

	var result JobResult
	result.JobID = jobID
	result.Profile = input.Profile

	action := strings.TrimSpace(input.Action)
	if action == "" {
		switch topic {
		case topicChat, topicGenerate:
			action = "chat"
		case topicEmbed:
			action = "embed"
		case topicRerank:
			action = "rerank"
		case topicClassify:
			action = "classify"
		default:
			action = "chat"
		}
	}
	result.Action = action

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	switch action {
	case "chat", "generate":
		w.handleChat(ctx, params, &result)
	case "embed":
		w.handleEmbed(ctx, params, &result)
	case "rerank":
		w.handleRerank(ctx, params, &result)
	case "classify":
		w.handleClassify(ctx, params, &result)
	case "models.list":
		w.handleModelsList(ctx, &result)
	default:
		result.Error = fmt.Sprintf("unsupported action: %s", action)
	}

	result.DurationMs = time.Since(start).Milliseconds()
	slog.Info("cohere job completed", "job_id", jobID, "action", action, "duration_ms", result.DurationMs, "error", result.Error)
	return result, nil
}

func (w *Worker) handleChat(ctx context.Context, params map[string]any, result *JobResult) {
	var req cohereapi.ChatRequest
	if err := decodePayload(params, &req); err != nil {
		result.Error = err.Error()
		return
	}
	if !w.cfg.IsModelAllowed(req.Model) {
		result.Error = fmt.Sprintf("model %q not allowed", req.Model)
		return
	}

	resp, status, err := w.client.Chat(ctx, &req)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Text = resp.Text
	result.FinishReason = resp.FinishReason
	result.Citations = resp.Citations
	result.ToolCalls = resp.ToolCalls
	if resp.Meta != nil && resp.Meta.BilledUnits != nil {
		result.BilledUnits = resp.Meta.BilledUnits
	}
}

func (w *Worker) handleEmbed(ctx context.Context, params map[string]any, result *JobResult) {
	var req cohereapi.EmbedRequest
	if err := decodePayload(params, &req); err != nil {
		result.Error = err.Error()
		return
	}
	if req.InputType == "" {
		result.Error = "input_type is required for Cohere v3 embeddings (search_document, search_query, classification, clustering)"
		return
	}

	resp, status, err := w.client.Embed(ctx, &req)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Embeddings = resp.Embeddings
	if resp.Meta != nil && resp.Meta.BilledUnits != nil {
		result.BilledUnits = resp.Meta.BilledUnits
	}
}

func (w *Worker) handleRerank(ctx context.Context, params map[string]any, result *JobResult) {
	var req cohereapi.RerankRequest
	if err := decodePayload(params, &req); err != nil {
		result.Error = err.Error()
		return
	}

	resp, status, err := w.client.Rerank(ctx, &req)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Results = resp.Results
	if resp.Meta != nil && resp.Meta.BilledUnits != nil {
		result.BilledUnits = resp.Meta.BilledUnits
	}
}

func (w *Worker) handleClassify(ctx context.Context, params map[string]any, result *JobResult) {
	var req cohereapi.ClassifyRequest
	if err := decodePayload(params, &req); err != nil {
		result.Error = err.Error()
		return
	}

	resp, status, err := w.client.Classify(ctx, &req)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Results = resp.Classifications
	if resp.Meta != nil && resp.Meta.BilledUnits != nil {
		result.BilledUnits = resp.Meta.BilledUnits
	}
}

func (w *Worker) handleModelsList(ctx context.Context, result *JobResult) {
	resp, status, err := w.client.ListModels(ctx)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
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
