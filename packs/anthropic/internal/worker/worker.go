package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/anthropic/internal/anthropicapi"
	"github.com/cordum-io/cordum-packs/packs/anthropic/internal/config"
	"github.com/cordum-io/cordum-packs/packs/anthropic/internal/gatewayclient"
)

const (
	topicMessages        = "job.anthropic.messages"
	topicMessagesStream  = "job.anthropic.messages.stream"
	topicMessagesTooluse = "job.anthropic.messages.tooluse"
	topicBatch           = "job.anthropic.batch"
	topicBatchRead       = "job.anthropic.batch.read"

	governancePollInterval = 500 * time.Millisecond
	governanceTimeout      = 2 * time.Minute
	maxToolUseIterations   = 10
)

// Worker handles Anthropic pack jobs.
type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
	gwClient *gatewayclient.Client
}

// JobInput is the incoming job payload.
type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
	Auth      *InlineAuth    `json:"auth,omitempty"`
}

// InlineAuth holds optional inline authentication.
type InlineAuth struct {
	APIKey    string `json:"api_key"`
	APIKeyEnv string `json:"api_key_env"`
}

// JobResult is the output payload for all Anthropic jobs.
type JobResult struct {
	JobID        string                        `json:"job_id"`
	Profile      string                        `json:"profile"`
	Action       string                        `json:"action"`
	StatusCode   int                           `json:"status_code"`
	RequestID    string                        `json:"request_id,omitempty"`
	DurationMs   int64                         `json:"duration_ms"`
	Model        string                        `json:"model,omitempty"`
	StopReason   string                        `json:"stop_reason,omitempty"`
	Content      []anthropicapi.ContentBlock   `json:"content,omitempty"`
	Usage        *anthropicapi.Usage           `json:"usage,omitempty"`
	CostEstimate *anthropicapi.CostEstimate    `json:"cost_estimate,omitempty"`
	Result       any                           `json:"result,omitempty"`
	Error        string                        `json:"error,omitempty"`
}

// New creates a new Anthropic worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "anthropic")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("redis store: %w", err)
	}

	agent := &runtime.Agent{
		NATS:     nc,
		Store:    store,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	var gwClient *gatewayclient.Client
	if cfg.ToolGovernance {
		gwClient = gatewayclient.New(cfg.GatewayURL, cfg.APIKey, cfg.TenantID)
	}

	w := &Worker{
		cfg:      cfg,
		agent:    agent,
		natsConn: nc,
		workerID: workerID,
		gwClient: gwClient,
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
		subjects = []string{topicMessages, topicMessagesStream, topicMessagesTooluse, topicBatch, topicBatchRead}
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

	slog.Info("anthropic worker started",
		"worker_id", w.workerID,
		"subjects", subjects,
		"tool_governance", w.cfg.ToolGovernance,
		"thinking_enabled", w.cfg.ThinkingEnabled,
	)

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

	// Create a stdlib context with timeout for HTTP calls
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.RequestTimeout)
	defer cancel()

	payload = normalizePayload(payload)

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		return JobResult{JobID: jobID, Error: fmt.Sprintf("decode input: %v", err)}, nil
	}

	// Resolve profile and build API client
	profile := w.cfg.ResolveProfile(input.Profile)
	apiKey := w.resolveAPIKey(profile, input.Auth)
	if apiKey == "" {
		return JobResult{JobID: jobID, Error: "no API key configured"}, nil
	}

	client := anthropicapi.NewClient(
		profile.BaseURL,
		apiKey,
		profile.APIVersion,
		anthropicapi.WithUserAgent(profile.UserAgent),
	)

	var result JobResult
	result.JobID = jobID
	result.Profile = profile.Name

	switch topic {
	case topicMessages:
		result.Action = "messages.create"
		w.handleMessages(ctx, client, profile, input, &result)
	case topicMessagesStream:
		result.Action = "messages.create.stream"
		w.handleStream(ctx, jobID, client, profile, input, &result)
	case topicMessagesTooluse:
		result.Action = "messages.create.tooluse"
		w.handleToolUse(ctx, jobID, client, profile, input, &result)
	case topicBatch, topicBatchRead:
		w.handleBatch(ctx, client, input, &result)
	default:
		w.handleByAction(ctx, jobID, client, profile, input, &result)
	}

	result.DurationMs = time.Since(start).Milliseconds()

	slog.Info("anthropic job completed",
		"job_id", jobID,
		"topic", topic,
		"action", result.Action,
		"duration_ms", result.DurationMs,
		"status_code", result.StatusCode,
		"input_tokens", tokenCount(result.Usage, true),
		"output_tokens", tokenCount(result.Usage, false),
		"error", result.Error,
	)

	return result, nil
}

// handleMessages processes a standard (non-streaming) messages request.
func (w *Worker) handleMessages(ctx context.Context, client *anthropicapi.Client, profile config.Profile, input JobInput, result *JobResult) {
	req, err := buildMessagesRequest(input.Params, profile, w.cfg)
	if err != nil {
		result.Error = err.Error()
		return
	}

	resp, status, requestID, err := client.CreateMessage(ctx, req)
	result.StatusCode = status
	result.RequestID = requestID
	if err != nil {
		result.Error = err.Error()
		return
	}

	result.Model = resp.Model
	result.StopReason = resp.StopReason
	result.Content = resp.Content
	result.Usage = &resp.Usage
	cost := anthropicapi.EstimateCost(resp.Model, resp.Usage)
	result.CostEstimate = &cost
}

// handleStream processes a streaming messages request, collecting chunks via NATS.
func (w *Worker) handleStream(ctx context.Context, jobID string, client *anthropicapi.Client, profile config.Profile, input JobInput, result *JobResult) {
	req, err := buildMessagesRequest(input.Params, profile, w.cfg)
	if err != nil {
		result.Error = err.Error()
		return
	}

	reader, status, requestID, err := client.CreateMessageStream(ctx, req)
	result.StatusCode = status
	result.RequestID = requestID
	if err != nil {
		result.Error = err.Error()
		return
	}
	defer reader.Close()

	// Collect the full streamed response
	var textBuilder strings.Builder
	var usage anthropicapi.Usage
	var model, stopReason string

	for {
		evt, err := reader.Next()
		if err != nil {
			break
		}

		switch evt.Type {
		case "message_start":
			var msgStart struct {
				Message struct {
					Model string            `json:"model"`
					Usage anthropicapi.Usage `json:"usage"`
				} `json:"message"`
			}
			if json.Unmarshal(evt.Data, &msgStart) == nil {
				model = msgStart.Message.Model
				usage.InputTokens = msgStart.Message.Usage.InputTokens
			}

		case "content_block_delta":
			var delta struct {
				Delta struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"delta"`
			}
			if json.Unmarshal(evt.Data, &delta) == nil && delta.Delta.Type == "text_delta" {
				textBuilder.WriteString(delta.Delta.Text)

				// Publish progress chunk via NATS for real-time streaming
				if w.natsConn != nil {
					chunkData, _ := json.Marshal(map[string]any{
						"type": "content_block_delta",
						"text": delta.Delta.Text,
					})
					progressSubject := fmt.Sprintf("sys.job.%s.stream", jobID)
					_ = w.natsConn.Publish(progressSubject, chunkData)
				}
			}

		case "message_delta":
			var msgDelta struct {
				Delta struct {
					StopReason string `json:"stop_reason"`
				} `json:"delta"`
				Usage struct {
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			}
			if json.Unmarshal(evt.Data, &msgDelta) == nil {
				stopReason = msgDelta.Delta.StopReason
				usage.OutputTokens = msgDelta.Usage.OutputTokens
			}
		}
	}

	result.Model = model
	result.StopReason = stopReason
	if textBuilder.Len() > 0 {
		result.Content = []anthropicapi.ContentBlock{{Type: "text", Text: textBuilder.String()}}
	}
	result.Usage = &usage
	cost := anthropicapi.EstimateCost(model, usage)
	result.CostEstimate = &cost
}

// handleToolUse implements the CAP tool governance flow.
// When the model responds with tool_use blocks, each tool call is submitted
// to the gateway for Safety Kernel evaluation before execution.
func (w *Worker) handleToolUse(ctx context.Context, jobID string, client *anthropicapi.Client, profile config.Profile, input JobInput, result *JobResult) {
	req, err := buildMessagesRequest(input.Params, profile, w.cfg)
	if err != nil {
		result.Error = err.Error()
		return
	}

	if len(req.Tools) == 0 {
		result.Error = "tool_use topic requires at least one tool definition"
		return
	}

	var totalUsage anthropicapi.Usage

	// Iterative tool use loop: send request -> get tool_use -> govern -> collect results -> continue
	for iteration := 0; iteration < maxToolUseIterations; iteration++ {
		resp, status, requestID, err := client.CreateMessage(ctx, req)
		result.StatusCode = status
		if iteration == 0 {
			result.RequestID = requestID
		}
		if err != nil {
			result.Error = err.Error()
			return
		}

		totalUsage.InputTokens += resp.Usage.InputTokens
		totalUsage.OutputTokens += resp.Usage.OutputTokens
		totalUsage.CacheCreationInputTokens += resp.Usage.CacheCreationInputTokens
		totalUsage.CacheReadInputTokens += resp.Usage.CacheReadInputTokens

		result.Model = resp.Model

		// If no tool_use in response, we're done
		if resp.StopReason != "tool_use" {
			result.StopReason = resp.StopReason
			result.Content = resp.Content
			result.Usage = &totalUsage
			cost := anthropicapi.EstimateCost(resp.Model, totalUsage)
			result.CostEstimate = &cost
			return
		}

		// Extract tool_use blocks and process through governance
		toolResults, err := w.governToolCalls(ctx, jobID, resp.Content)
		if err != nil {
			result.Error = fmt.Sprintf("tool governance failed: %v", err)
			result.Usage = &totalUsage
			cost := anthropicapi.EstimateCost(resp.Model, totalUsage)
			result.CostEstimate = &cost
			return
		}

		// Build continuation: append assistant response + tool results
		req.Messages = append(req.Messages,
			anthropicapi.Message{Role: "assistant", Content: resp.Content},
			anthropicapi.Message{Role: "user", Content: toolResults},
		)
	}

	result.Error = fmt.Sprintf("tool use loop exceeded maximum iterations (%d)", maxToolUseIterations)
	result.Usage = &totalUsage
	cost := anthropicapi.EstimateCost(result.Model, totalUsage)
	result.CostEstimate = &cost
}

// governToolCalls submits each tool_use block through the gateway for Safety Kernel approval.
func (w *Worker) governToolCalls(ctx context.Context, parentJobID string, content []anthropicapi.ContentBlock) ([]anthropicapi.ContentBlock, error) {
	if w.gwClient == nil {
		return nil, fmt.Errorf("tool governance enabled but gateway client not configured")
	}

	var results []anthropicapi.ContentBlock

	for _, block := range content {
		if block.Type != "tool_use" {
			continue
		}

		slog.Info("governing tool call",
			"tool_name", block.Name,
			"tool_id", block.ID,
			"parent_job_id", parentJobID,
		)

		// Submit governed job for this tool call
		submitReq := &gatewayclient.JobSubmitRequest{
			Prompt:     fmt.Sprintf("Governed tool call: %s", block.Name),
			Topic:      fmt.Sprintf("job.anthropic.tool.%s", block.Name),
			Context:    map[string]any{"tool_name": block.Name, "arguments": block.Input, "tool_use_id": block.ID},
			PackID:     "anthropic",
			Capability: fmt.Sprintf("anthropic.tool.%s", block.Name),
			RiskTags:   []string{"tool", "governance", "write"},
			Requires:   []string{"network:egress"},
			Labels:     map[string]string{"tool_name": block.Name, "parent_job_id": parentJobID},
		}

		submitResp, err := w.gwClient.SubmitJob(ctx, submitReq)
		if err != nil {
			// Tool call denied or gateway error — return error as tool result
			results = append(results, anthropicapi.ContentBlock{
				Type:      "tool_result",
				ToolUseID: block.ID,
				Content_:  fmt.Sprintf("Tool call governance failed: %v", err),
				IsError:   true,
			})
			continue
		}

		// Poll for governance decision
		outcome, err := w.waitForGovernanceResult(ctx, submitResp.JobID)
		if err != nil {
			results = append(results, anthropicapi.ContentBlock{
				Type:      "tool_result",
				ToolUseID: block.ID,
				Content_:  fmt.Sprintf("Tool call governance timeout: %v", err),
				IsError:   true,
			})
			continue
		}

		if !outcome.approved {
			results = append(results, anthropicapi.ContentBlock{
				Type:      "tool_result",
				ToolUseID: block.ID,
				Content_:  fmt.Sprintf("Tool call denied by policy: %s", outcome.reason),
				IsError:   true,
			})
			continue
		}

		// Approved — include the result
		resultContent := "Tool call approved and executed successfully."
		if outcome.result != nil {
			if resultJSON, err := json.Marshal(outcome.result); err == nil {
				resultContent = string(resultJSON)
			}
		}

		results = append(results, anthropicapi.ContentBlock{
			Type:      "tool_result",
			ToolUseID: block.ID,
			Content_:  resultContent,
		})
	}

	return results, nil
}

type governanceOutcome struct {
	approved bool
	result   any
	reason   string
}

// waitForGovernanceResult polls the gateway until the governed job reaches a terminal state.
func (w *Worker) waitForGovernanceResult(ctx context.Context, jobID string) (*governanceOutcome, error) {
	govCtx, cancel := context.WithTimeout(ctx, governanceTimeout)
	defer cancel()

	ticker := time.NewTicker(governancePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-govCtx.Done():
			return nil, fmt.Errorf("governance decision timeout for job %s", jobID)
		case <-ticker.C:
			job, err := w.gwClient.GetJob(govCtx, jobID)
			if err != nil {
				continue // Retry on transient errors
			}

			status := normalizeJobStatus(job["status"])
			if !terminalJobStatus(status) {
				continue
			}

			switch status {
			case "succeeded":
				return &governanceOutcome{
					approved: true,
					result:   extractJobResult(job),
				}, nil
			case "denied":
				reason := extractJobError(job)
				if reason == "" {
					reason = "denied by policy"
				}
				return &governanceOutcome{
					approved: false,
					reason:   reason,
				}, nil
			default:
				errMsg := extractJobError(job)
				if errMsg == "" {
					errMsg = fmt.Sprintf("job ended with status: %s", status)
				}
				return &governanceOutcome{
					approved: false,
					reason:   errMsg,
				}, nil
			}
		}
	}
}

// handleBatch routes batch operations.
func (w *Worker) handleBatch(ctx context.Context, client *anthropicapi.Client, input JobInput, result *JobResult) {
	action := strings.TrimSpace(input.Action)
	if action == "" {
		action = stringFromMap(input.Params, "action")
	}

	switch action {
	case "batch.create":
		result.Action = "batch.create"
		w.handleBatchCreate(ctx, client, input, result)
	case "batch.list":
		result.Action = "batch.list"
		w.handleBatchList(ctx, client, input, result)
	case "batch.get":
		result.Action = "batch.get"
		w.handleBatchGet(ctx, client, input, result)
	case "batch.cancel":
		result.Action = "batch.cancel"
		w.handleBatchCancel(ctx, client, input, result)
	case "models.list":
		result.Action = "models.list"
		w.handleModelsList(ctx, client, result)
	default:
		result.Error = fmt.Sprintf("unsupported batch action: %s", action)
	}
}

func (w *Worker) handleBatchCreate(ctx context.Context, client *anthropicapi.Client, input JobInput, result *JobResult) {
	var batchReq anthropicapi.BatchRequest
	if err := decodePayload(input.Params, &batchReq); err != nil {
		result.Error = fmt.Sprintf("decode batch request: %v", err)
		return
	}
	resp, status, requestID, err := client.CreateBatch(ctx, &batchReq)
	result.StatusCode = status
	result.RequestID = requestID
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
}

func (w *Worker) handleBatchList(ctx context.Context, client *anthropicapi.Client, input JobInput, result *JobResult) {
	limit := intFromMap(input.Params, "limit")
	afterID := stringFromMap(input.Params, "after_id")
	resp, status, requestID, err := client.ListBatches(ctx, limit, afterID)
	result.StatusCode = status
	result.RequestID = requestID
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
}

func (w *Worker) handleBatchGet(ctx context.Context, client *anthropicapi.Client, input JobInput, result *JobResult) {
	batchID := stringFromMap(input.Params, "batch_id")
	if batchID == "" {
		result.Error = "batch_id required"
		return
	}
	resp, status, requestID, err := client.GetBatch(ctx, batchID)
	result.StatusCode = status
	result.RequestID = requestID
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
}

func (w *Worker) handleBatchCancel(ctx context.Context, client *anthropicapi.Client, input JobInput, result *JobResult) {
	batchID := stringFromMap(input.Params, "batch_id")
	if batchID == "" {
		result.Error = "batch_id required"
		return
	}
	resp, status, requestID, err := client.CancelBatch(ctx, batchID)
	result.StatusCode = status
	result.RequestID = requestID
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
}

func (w *Worker) handleModelsList(ctx context.Context, client *anthropicapi.Client, result *JobResult) {
	resp, status, requestID, err := client.ListModels(ctx)
	result.StatusCode = status
	result.RequestID = requestID
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Result = resp
}

// handleByAction routes based on the action field when topic doesn't match known patterns.
func (w *Worker) handleByAction(ctx context.Context, jobID string, client *anthropicapi.Client, profile config.Profile, input JobInput, result *JobResult) {
	action := strings.TrimSpace(input.Action)
	result.Action = action

	switch action {
	case "messages.create":
		w.handleMessages(ctx, client, profile, input, result)
	case "messages.create.stream":
		w.handleStream(ctx, jobID, client, profile, input, result)
	case "messages.create.tooluse":
		w.handleToolUse(ctx, jobID, client, profile, input, result)
	case "batch.create", "batch.list", "batch.get", "batch.cancel", "models.list":
		w.handleBatch(ctx, client, input, result)
	default:
		result.Error = fmt.Sprintf("unsupported action: %s", action)
	}
}

// resolveAPIKey determines the API key for a request.
func (w *Worker) resolveAPIKey(profile config.Profile, auth *InlineAuth) string {
	// Inline auth takes priority if allowed
	if auth != nil && w.cfg.AllowInlineAuth {
		if auth.APIKey != "" && w.cfg.AllowInlineSecrets {
			return auth.APIKey
		}
		if auth.APIKeyEnv != "" {
			if key := strings.TrimSpace(os.Getenv(auth.APIKeyEnv)); key != "" {
				return key
			}
		}
	}
	return profile.ResolveAPIKey()
}

// buildMessagesRequest converts params map to a typed MessagesRequest with validation.
func buildMessagesRequest(params map[string]any, profile config.Profile, cfg config.Config) (*anthropicapi.MessagesRequest, error) {
	var req anthropicapi.MessagesRequest
	if err := decodePayload(params, &req); err != nil {
		return nil, fmt.Errorf("decode messages params: %w", err)
	}

	if req.Model == "" {
		return nil, fmt.Errorf("model is required")
	}
	if !profile.IsModelAllowed(req.Model) {
		return nil, fmt.Errorf("model %q is not allowed by profile %q", req.Model, profile.Name)
	}

	if req.MaxTokens <= 0 {
		return nil, fmt.Errorf("max_tokens is required and must be positive")
	}
	if req.MaxTokens > profile.MaxTokensLimit {
		return nil, fmt.Errorf("max_tokens %d exceeds profile limit %d", req.MaxTokens, profile.MaxTokensLimit)
	}

	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("messages array is required and cannot be empty")
	}

	// Validate thinking configuration
	if req.Thinking != nil {
		if !profile.ThinkingEnabled && !cfg.ThinkingEnabled {
			return nil, fmt.Errorf("extended thinking is not enabled for profile %q", profile.Name)
		}
		if req.Thinking.BudgetTokens > profile.ThinkingMaxBudget {
			return nil, fmt.Errorf("thinking budget_tokens %d exceeds limit %d", req.Thinking.BudgetTokens, profile.ThinkingMaxBudget)
		}
	}

	return &req, nil
}

// --- Helper functions ---

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

func stringFromMap(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func intFromMap(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
	}
	return 0
}

func tokenCount(usage *anthropicapi.Usage, input bool) int {
	if usage == nil {
		return 0
	}
	if input {
		return usage.InputTokens
	}
	return usage.OutputTokens
}

// Job status helpers (mirroring sidecar-template patterns)

func normalizeJobStatus(value any) string {
	switch typed := value.(type) {
	case string:
		status := strings.TrimSpace(strings.ToLower(typed))
		status = strings.TrimPrefix(status, "job_status_")
		switch status {
		case "succeeded", "success":
			return "succeeded"
		case "failed", "failed_retryable", "failed_fatal":
			return "failed"
		case "cancelled", "canceled":
			return "cancelled"
		case "denied":
			return "denied"
		case "timeout", "timed_out":
			return "timeout"
		default:
			return status
		}
	case float64:
		return mapNumericStatus(typed)
	default:
		return ""
	}
}

func mapNumericStatus(value float64) string {
	switch int(value) {
	case 1:
		return "pending"
	case 2:
		return "scheduled"
	case 3:
		return "dispatched"
	case 4:
		return "running"
	case 5:
		return "succeeded"
	case 6, 10, 11:
		return "failed"
	case 7:
		return "cancelled"
	case 8:
		return "denied"
	case 9:
		return "timeout"
	default:
		return ""
	}
}

func terminalJobStatus(status string) bool {
	switch status {
	case "succeeded", "failed", "cancelled", "denied", "timeout":
		return true
	default:
		return false
	}
}

func extractJobResult(job map[string]any) any {
	for _, key := range []string{"result", "output", "payload", "data"} {
		if value, ok := job[key]; ok {
			return value
		}
	}
	return nil
}

func extractJobError(job map[string]any) string {
	for _, key := range []string{"error", "message", "reason"} {
		if value, ok := job[key]; ok {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return typed
				}
			case map[string]any:
				if message, ok := typed["message"].(string); ok && strings.TrimSpace(message) != "" {
					return message
				}
			}
		}
	}
	return ""
}
