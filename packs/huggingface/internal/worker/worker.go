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

	"github.com/cordum-io/cordum-packs/packs/huggingface/internal/config"
	"github.com/cordum-io/cordum-packs/packs/huggingface/internal/huggingfaceapi"
)

const (
	topicInference    = "job.huggingface.inference"
	topicEmbed        = "job.huggingface.embed"
	topicModels       = "job.huggingface.models"
	topicSpaces       = "job.huggingface.spaces"
	topicSpacesManage = "job.huggingface.spaces.manage"
)

// Worker handles HuggingFace pack jobs.
type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
	client   *huggingfaceapi.Client
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
	JobID         string  `json:"job_id"`
	Profile       string  `json:"profile"`
	Action        string  `json:"action"`
	StatusCode    int     `json:"status_code"`
	RequestID     string  `json:"request_id,omitempty"`
	DurationMs    int64   `json:"duration_ms"`
	ModelID       string  `json:"model_id,omitempty"`
	Task          string  `json:"task,omitempty"`
	Result        any     `json:"result,omitempty"`
	Embeddings    any     `json:"embeddings,omitempty"`
	Error         string  `json:"error,omitempty"`
	EstimatedTime float64 `json:"estimated_time,omitempty"`
}

// New creates a new HuggingFace worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "huggingface")
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
		client:   huggingfaceapi.NewClient(cfg.InferenceURL, cfg.HubURL, cfg.Token),
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
		subjects = []string{topicInference, topicEmbed, topicModels, topicSpaces, topicSpacesManage}
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
	slog.Info("huggingface worker started", "worker_id", w.workerID, "subjects", subjects)
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
		case topicInference:
			action = "inference"
		case topicEmbed:
			action = "embed"
		case topicModels:
			action = "models.search"
		case topicSpaces:
			action = "spaces.get"
		case topicSpacesManage:
			action = "spaces.restart"
		default:
			action = "inference"
		}
	}
	result.Action = action

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	switch action {
	case "inference":
		w.handleInference(ctx, params, &result)
	case "embed":
		w.handleEmbed(ctx, params, &result)
	case "models.search":
		w.handleModelSearch(ctx, params, &result)
	case "models.get":
		w.handleModelGet(ctx, params, &result)
	case "spaces.get":
		w.handleSpaceGet(ctx, params, &result)
	case "spaces.restart":
		w.handleSpaceRestart(ctx, params, &result)
	default:
		result.Error = fmt.Sprintf("unsupported action: %s", action)
	}

	result.DurationMs = time.Since(start).Milliseconds()
	slog.Info("huggingface job completed", "job_id", jobID, "action", action, "duration_ms", result.DurationMs, "error", result.Error)
	return result, nil
}

func (w *Worker) handleInference(ctx context.Context, params map[string]any, result *JobResult) {
	modelID, _ := params["model"].(string)
	if modelID == "" {
		result.Error = "model is required"
		return
	}
	task, _ := params["task"].(string)
	if !w.cfg.IsTaskAllowed(task) {
		result.Error = fmt.Sprintf("task %q is not allowed", task)
		return
	}

	waitForModel := false
	if opts, ok := params["options"].(map[string]any); ok {
		if wfm, ok := opts["wait_for_model"].(bool); ok {
			waitForModel = wfm
		}
	}

	body := map[string]any{"inputs": params["inputs"]}
	if p, ok := params["parameters"].(map[string]any); ok {
		body["parameters"] = p
	}

	resp, status, err := w.client.Inference(ctx, modelID, body, waitForModel)
	result.StatusCode = status
	result.ModelID = modelID
	result.Task = task
	if err != nil {
		result.Error = err.Error()
		if respMap, ok := resp.(map[string]any); ok {
			if et, ok := respMap["estimated_time"].(float64); ok {
				result.EstimatedTime = et
			}
		}
		return
	}
	result.Result = resp
}

func (w *Worker) handleEmbed(ctx context.Context, params map[string]any, result *JobResult) {
	modelID, _ := params["model"].(string)
	if modelID == "" {
		result.Error = "model is required"
		return
	}

	waitForModel := false
	if opts, ok := params["options"].(map[string]any); ok {
		if wfm, ok := opts["wait_for_model"].(bool); ok {
			waitForModel = wfm
		}
	}

	resp, status, err := w.client.Embed(ctx, modelID, params["inputs"], waitForModel)
	result.StatusCode = status
	result.ModelID = modelID
	result.Task = "feature-extraction"
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Embeddings = resp
}

func (w *Worker) handleModelSearch(ctx context.Context, params map[string]any, result *JobResult) {
	resp, status, err := w.client.SearchModels(ctx, params)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
}

func (w *Worker) handleModelGet(ctx context.Context, params map[string]any, result *JobResult) {
	modelID, _ := params["model_id"].(string)
	if modelID == "" {
		modelID, _ = params["model"].(string)
	}
	resp, status, err := w.client.GetModel(ctx, modelID)
	result.StatusCode = status
	result.ModelID = modelID
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
}

func (w *Worker) handleSpaceGet(ctx context.Context, params map[string]any, result *JobResult) {
	spaceID, _ := params["space_id"].(string)
	resp, status, err := w.client.GetSpace(ctx, spaceID)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
}

func (w *Worker) handleSpaceRestart(ctx context.Context, params map[string]any, result *JobResult) {
	spaceID, _ := params["space_id"].(string)
	resp, status, err := w.client.RestartSpace(ctx, spaceID)
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
