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

	"github.com/cordum-io/cordum-packs/packs/mistral/internal/config"
	"github.com/cordum-io/cordum-packs/packs/mistral/internal/mistralapi"
)

const (
	topicChat       = "job.mistral.chat"
	topicChatStream = "job.mistral.chat.stream"
	topicEmbed      = "job.mistral.embed"
	topicCode       = "job.mistral.code"
	topicFIM        = "job.mistral.fim"
)

// Worker handles Mistral pack jobs.
type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
	client   *mistralapi.Client
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
	JobID        string                  `json:"job_id"`
	Profile      string                  `json:"profile"`
	Action       string                  `json:"action"`
	StatusCode   int                     `json:"status_code"`
	RequestID    string                  `json:"request_id,omitempty"`
	DurationMs   int64                   `json:"duration_ms"`
	Model        string                  `json:"model,omitempty"`
	Content      string                  `json:"content,omitempty"`
	FinishReason string                  `json:"finish_reason,omitempty"`
	ToolCalls    any                     `json:"tool_calls,omitempty"`
	Usage        *mistralapi.Usage       `json:"usage,omitempty"`
	CostEstimate *mistralapi.CostEstimate `json:"cost_estimate,omitempty"`
	Embeddings   any                     `json:"embeddings,omitempty"`
	Result       any                     `json:"result,omitempty"`
	Error        string                  `json:"error,omitempty"`
}

// New creates a new Mistral worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("MISTRAL_API_KEY is required")
	}

	workerID := resolveWorkerID("", "mistral")
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

	client := mistralapi.NewClient(cfg.BaseURL, cfg.APIKey)

	w := &Worker{
		cfg:      cfg,
		agent:    runtimeAgent,
		natsConn: nc,
		workerID: workerID,
		client:   client,
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

// Run starts the worker.
func (w *Worker) Run(ctx context.Context) error {
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}

	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{topicChat, topicChatStream, topicEmbed, topicCode, topicFIM}
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

	slog.Info("mistral worker started", "worker_id", w.workerID, "subjects", subjects)
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

	var result JobResult
	result.JobID = jobID
	result.Profile = input.Profile

	// Determine action from topic or input
	action := strings.TrimSpace(input.Action)
	if action == "" {
		switch topic {
		case topicChat:
			action = "chat.completions"
		case topicChatStream:
			action = "chat.completions.stream"
		case topicEmbed:
			action = "embeddings"
		case topicCode, topicFIM:
			action = "fim.completions"
		default:
			action = "chat.completions"
		}
	}
	result.Action = action

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	switch action {
	case "chat.completions":
		w.handleChat(ctx, params, &result)
	case "chat.completions.stream":
		w.handleChatStream(ctx, jobID, params, &result)
	case "embeddings":
		w.handleEmbedding(ctx, params, &result)
	case "fim.completions":
		w.handleFIM(ctx, params, &result)
	case "models.list":
		w.handleModelsList(ctx, &result)
	default:
		result.Error = fmt.Sprintf("unsupported action: %s", action)
	}

	result.DurationMs = time.Since(start).Milliseconds()

	slog.Info("mistral job completed",
		"job_id", jobID, "action", action,
		"duration_ms", result.DurationMs,
		"prompt_tokens", tokenCount(result.Usage, true),
		"completion_tokens", tokenCount(result.Usage, false),
		"error", result.Error,
	)

	return result, nil
}

func (w *Worker) handleChat(ctx context.Context, params map[string]any, result *JobResult) {
	var req mistralapi.ChatRequest
	if err := decodePayload(params, &req); err != nil {
		result.Error = fmt.Sprintf("decode chat params: %v", err)
		return
	}

	if !w.cfg.IsModelAllowed(req.Model) {
		result.Error = fmt.Sprintf("model %q is not allowed", req.Model)
		return
	}
	if req.MaxTokens != nil && *req.MaxTokens > w.cfg.MaxTokensLimit {
		result.Error = fmt.Sprintf("max_tokens %d exceeds limit %d", *req.MaxTokens, w.cfg.MaxTokensLimit)
		return
	}
	if w.cfg.SafePrompt {
		req.SafePrompt = true
	}

	resp, status, err := w.client.ChatCompletion(ctx, &req)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Model = resp.Model
	result.Usage = &resp.Usage
	cost := mistralapi.EstimateCost(resp.Model, resp.Usage)
	result.CostEstimate = &cost

	if len(resp.Choices) > 0 {
		result.Content = resp.Choices[0].Message.Content
		result.FinishReason = resp.Choices[0].FinishReason
		result.ToolCalls = resp.Choices[0].Message.ToolCalls
	}
}

func (w *Worker) handleChatStream(ctx context.Context, jobID string, params map[string]any, result *JobResult) {
	var req mistralapi.ChatRequest
	if err := decodePayload(params, &req); err != nil {
		result.Error = fmt.Sprintf("decode chat params: %v", err)
		return
	}

	if !w.cfg.IsModelAllowed(req.Model) {
		result.Error = fmt.Sprintf("model %q is not allowed", req.Model)
		return
	}

	scanner, body, status, err := w.client.ChatCompletionStream(ctx, &req)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}
	defer body.Close()

	var textBuilder strings.Builder
	var finishReason string
	var usage mistralapi.Usage

	for scanner.Scan() {
		line := scanner.Text()
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			if v == "[DONE]" {
				break
			}
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
					FinishReason string `json:"finish_reason"`
				} `json:"choices"`
				Usage *mistralapi.Usage `json:"usage,omitempty"`
			}
			if json.Unmarshal([]byte(v), &chunk) == nil {
				if len(chunk.Choices) > 0 {
					if chunk.Choices[0].Delta.Content != "" {
						textBuilder.WriteString(chunk.Choices[0].Delta.Content)
						// Publish progress via NATS
						if w.natsConn != nil {
							chunkData, _ := json.Marshal(map[string]any{"text": chunk.Choices[0].Delta.Content})
							_ = w.natsConn.Publish(fmt.Sprintf("sys.job.%s.stream", jobID), chunkData)
						}
					}
					if chunk.Choices[0].FinishReason != "" {
						finishReason = chunk.Choices[0].FinishReason
					}
				}
				if chunk.Usage != nil {
					usage = *chunk.Usage
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		result.Error = fmt.Sprintf("stream read error: %v", err)
		return
	}

	result.Content = textBuilder.String()
	result.FinishReason = finishReason
	result.Usage = &usage
	if usage.TotalTokens > 0 {
		cost := mistralapi.EstimateCost(req.Model, usage)
		result.CostEstimate = &cost
	}
}

func (w *Worker) handleEmbedding(ctx context.Context, params map[string]any, result *JobResult) {
	var req mistralapi.EmbeddingRequest
	if err := decodePayload(params, &req); err != nil {
		result.Error = fmt.Sprintf("decode embedding params: %v", err)
		return
	}
	if req.Model == "" {
		req.Model = "mistral-embed"
	}

	resp, status, err := w.client.CreateEmbedding(ctx, &req)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Model = resp.Model
	result.Usage = &resp.Usage
	cost := mistralapi.EstimateCost(resp.Model, resp.Usage)
	result.CostEstimate = &cost

	embeddings := make([][]float64, len(resp.Data))
	for i, d := range resp.Data {
		embeddings[i] = d.Embedding
	}
	result.Embeddings = embeddings
}

func (w *Worker) handleFIM(ctx context.Context, params map[string]any, result *JobResult) {
	var req mistralapi.FIMRequest
	if err := decodePayload(params, &req); err != nil {
		result.Error = fmt.Sprintf("decode FIM params: %v", err)
		return
	}
	if req.Model == "" {
		req.Model = "codestral-latest"
	}
	if req.Prompt == "" {
		result.Error = "prompt is required for FIM"
		return
	}

	resp, status, err := w.client.FIMCompletion(ctx, &req)
	result.StatusCode = status
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Model = resp.Model
	result.Usage = &resp.Usage
	cost := mistralapi.EstimateCost(resp.Model, resp.Usage)
	result.CostEstimate = &cost

	if len(resp.Choices) > 0 {
		result.Content = resp.Choices[0].Text
		result.FinishReason = resp.Choices[0].FinishReason
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

// --- Helpers ---

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

func tokenCount(usage *mistralapi.Usage, isPrompt bool) int {
	if usage == nil {
		return 0
	}
	if isPrompt {
		return usage.PromptTokens
	}
	return usage.CompletionTokens
}
