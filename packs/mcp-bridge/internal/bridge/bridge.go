package bridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/mcp-bridge/internal/mcp"
)

const (
	defaultProtocolVersion = "2025-11-25"
	legacyProtocolVersion  = "2025-06-18"
)

var supportedProtocolVersions = []string{
	defaultProtocolVersion,
	legacyProtocolVersion,
}

type Config struct {
	GatewayURL    string
	APIKey        string
	NatsURL       string
	RedisURL      string
	Pool          string
	Subjects      []string
	Queue         string
	JobTopic      string
	PackID        string
	ServerName    string
	ServerVersion string
	CallTimeout   time.Duration
	PollInterval  time.Duration
	MaxParallel   int32
}

type Bridge struct {
	cfg       Config
	client    *gatewayClient
	redis     *redis.Client
	worker    *runtime.Worker
	pending   map[string]chan callResult
	mu        sync.Mutex
	tools     []mcp.Tool
	templates []mcp.ResourceTemplate
}

type callResult struct {
	payload any
	err     error
	isError bool
}

func New(cfg Config) (*Bridge, error) {
	if cfg.GatewayURL == "" {
		return nil, fmt.Errorf("gateway url required")
	}
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}
	if cfg.Pool == "" {
		cfg.Pool = "mcp-bridge"
	}
	if len(cfg.Subjects) == 0 {
		cfg.Subjects = []string{"job.mcp-bridge.*"}
	}
	if cfg.JobTopic == "" {
		cfg.JobTopic = "job.mcp-bridge.tool"
	}
	if cfg.PackID == "" {
		cfg.PackID = "mcp-bridge"
	}
	if cfg.ServerName == "" {
		cfg.ServerName = "cordum-mcp-bridge"
	}
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "0.2.1"
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 30 * time.Second
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 750 * time.Millisecond
	}

	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opts)

	worker, err := runtime.NewWorker(runtime.Config{
		Pool:            cfg.Pool,
		Subjects:        cfg.Subjects,
		Queue:           cfg.Queue,
		NatsURL:         cfg.NatsURL,
		MaxParallelJobs: cfg.MaxParallel,
		Capabilities:    []string{"mcp-bridge"},
		Labels:          map[string]string{"adapter": "mcp-bridge"},
		Type:            "mcp-bridge",
	})
	if err != nil {
		return nil, err
	}

	b := &Bridge{
		cfg:     cfg,
		client:  newGatewayClient(cfg.GatewayURL, cfg.APIKey),
		redis:   client,
		worker:  worker,
		pending: map[string]chan callResult{},
	}
	b.tools = b.buildTools()
	b.templates = b.buildResourceTemplates()
	return b, nil
}

func (b *Bridge) Close() error {
	if b.worker != nil {
		_ = b.worker.Close()
	}
	if b.redis != nil {
		_ = b.redis.Close()
	}
	return nil
}

func (b *Bridge) RunWorker(ctx context.Context) error {
	return b.worker.Run(ctx, b.handleJob)
}

func (b *Bridge) Initialize(ctx context.Context, params map[string]any) (mcp.InitializeResult, error) {
	protocolVersion, err := negotiateProtocolVersion(stringArg(params, "protocolVersion"))
	if err != nil {
		return mcp.InitializeResult{}, err
	}
	return mcp.InitializeResult{
		ProtocolVersion: protocolVersion,
		ServerInfo: mcp.ServerInfo{
			Name:    b.cfg.ServerName,
			Version: b.cfg.ServerVersion,
		},
		Capabilities: mcp.Capabilities{
			Tools:     map[string]any{},
			Resources: map[string]any{},
		},
	}, nil
}

func (b *Bridge) ListTools(ctx context.Context, cursor string) (mcp.ToolListResult, error) {
	_ = cursor
	return mcp.ToolListResult{Tools: b.tools}, nil
}

func (b *Bridge) CallTool(ctx context.Context, name string, args map[string]any) (mcp.ToolCallResult, error) {
	if !b.supportsTool(name) {
		return mcp.ToolCallResult{Content: []mcp.ContentItem{{Type: "text", Text: "unsupported tool"}}, IsError: true}, nil
	}
	result, err := b.submitToolJob(ctx, name, args)
	payload, _ := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.ToolCallResult{Content: []mcp.ContentItem{{Type: "text", MimeType: "application/json", Text: string(payload)}}, IsError: true}, nil
	}
	return mcp.ToolCallResult{Content: []mcp.ContentItem{{Type: "text", MimeType: "application/json", Text: string(payload)}}}, nil
}

func (b *Bridge) ListResources(ctx context.Context, cursor string) (mcp.ResourceListResult, error) {
	_ = cursor
	return mcp.ResourceListResult{Resources: []mcp.Resource{}}, nil
}

func (b *Bridge) ListResourceTemplates(ctx context.Context, cursor string) (mcp.ResourceTemplateListResult, error) {
	_ = cursor
	return mcp.ResourceTemplateListResult{ResourceTemplates: b.templates}, nil
}

func (b *Bridge) ReadResource(ctx context.Context, uri string) (mcp.ResourceReadResult, error) {
	content, err := b.readResource(ctx, uri)
	if err != nil {
		return mcp.ResourceReadResult{}, err
	}
	return mcp.ResourceReadResult{Contents: []mcp.ResourceContent{content}}, nil
}

func (b *Bridge) supportsTool(name string) bool {
	for _, tool := range b.tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func (b *Bridge) handleJob(ctx context.Context, req *v1.JobRequest) (*v1.JobResult, error) {
	jobID := req.GetJobId()
	payload, err := b.fetchJobContext(ctx, req.GetContextPtr())
	if err != nil {
		b.complete(jobID, nil, err)
		return &v1.JobResult{JobId: jobID, Status: v1.JobStatus_JOB_STATUS_FAILED, ErrorMessage: err.Error()}, err
	}
	toolName, args, err := extractToolCall(payload)
	if err != nil {
		b.complete(jobID, nil, err)
		return &v1.JobResult{JobId: jobID, Status: v1.JobStatus_JOB_STATUS_FAILED, ErrorMessage: err.Error()}, err
	}
	output, err := b.executeTool(ctx, toolName, args)
	if err != nil {
		b.complete(jobID, map[string]any{"job_id": jobID, "error": err.Error()}, err)
		return &v1.JobResult{JobId: jobID, Status: v1.JobStatus_JOB_STATUS_FAILED, ErrorMessage: err.Error()}, err
	}
	resultPayload := map[string]any{
		"job_id": jobID,
		"tool":   toolName,
		"output": output,
	}
	ptr, storeErr := b.storeResult(ctx, jobID, resultPayload)
	if storeErr != nil {
		err = storeErr
		b.complete(jobID, resultPayload, err)
		return &v1.JobResult{JobId: jobID, Status: v1.JobStatus_JOB_STATUS_FAILED, ErrorMessage: err.Error()}, err
	}
	b.complete(jobID, resultPayload, nil)
	return &v1.JobResult{JobId: jobID, Status: v1.JobStatus_JOB_STATUS_SUCCEEDED, ResultPtr: ptr}, nil
}

func (b *Bridge) submitToolJob(ctx context.Context, name string, args map[string]any) (any, error) {
	jobReq := buildJobRequest(name, args, b.cfg)
	resp, err := b.client.SubmitJob(ctx, jobReq)
	if err != nil {
		return nil, err
	}
	pending := b.register(resp.JobID)
	defer b.unregister(resp.JobID)

	timeout := time.NewTimer(b.cfg.CallTimeout)
	defer timeout.Stop()
	poll := time.NewTicker(b.cfg.PollInterval)
	defer poll.Stop()

	for {
		select {
		case result := <-pending:
			if result.err != nil {
				return result.payload, result.err
			}
			return result.payload, nil
		case <-poll.C:
			job, err := b.client.GetJob(ctx, resp.JobID)
			if err != nil {
				continue
			}
			if job.IsTerminal() {
				return job.AsResult(), job.AsError()
			}
		case <-timeout.C:
			return nil, fmt.Errorf("tool call timed out after %s", b.cfg.CallTimeout)
		case <-ctx.Done():
			cancelCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = b.client.CancelJob(cancelCtx, resp.JobID)
			cancel()
			return nil, ctx.Err()
		}
	}
}

func (b *Bridge) register(jobID string) chan callResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan callResult, 1)
	b.pending[jobID] = ch
	return ch
}

func (b *Bridge) unregister(jobID string) {
	b.mu.Lock()
	delete(b.pending, jobID)
	b.mu.Unlock()
}

func (b *Bridge) complete(jobID string, payload any, err error) {
	b.mu.Lock()
	ch := b.pending[jobID]
	b.mu.Unlock()
	if ch == nil {
		return
	}
	ch <- callResult{payload: payload, err: err, isError: err != nil}
}

func (b *Bridge) fetchJobContext(ctx context.Context, ptr string) (map[string]any, error) {
	if ptr == "" {
		return nil, fmt.Errorf("context_ptr missing")
	}
	mem, err := b.client.GetMemory(ctx, ptr)
	if err != nil {
		return nil, err
	}
	payload, ok := mem.JSON.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected context format")
	}
	return payload, nil
}

func extractToolCall(payload map[string]any) (string, map[string]any, error) {
	ctx, ok := payload["context"].(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("tool context missing")
	}
	name, _ := ctx["tool"].(string)
	if name == "" {
		return "", nil, fmt.Errorf("tool name missing")
	}
	args := map[string]any{}
	if raw, ok := ctx["args"].(map[string]any); ok {
		args = raw
	}
	return name, args, nil
}

func (b *Bridge) storeResult(ctx context.Context, jobID string, payload any) (string, error) {
	if b.redis == nil {
		return "", fmt.Errorf("redis client unavailable")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	key := "res:" + jobID
	if err := b.redis.Set(ctx, key, data, 0).Err(); err != nil {
		return "", err
	}
	return "redis://" + key, nil
}

func (b *Bridge) executeTool(ctx context.Context, name string, args map[string]any) (any, error) {
	switch name {
	case "cordum.workflow.run":
		workflowID := stringArg(args, "workflow_id")
		if workflowID == "" {
			return nil, fmt.Errorf("workflow_id required")
		}
		input := map[string]any{}
		if raw, ok := args["input"].(map[string]any); ok {
			input = raw
		}
		dryRun := boolArg(args, "dry_run")
		idempotency := stringArg(args, "idempotency_key")
		return b.client.StartRun(ctx, workflowID, input, dryRun, idempotency)
	case "cordum.workflow.rerun":
		runID := stringArg(args, "run_id")
		if runID == "" {
			return nil, fmt.Errorf("run_id required")
		}
		fromStep := stringArg(args, "from_step")
		dryRun := boolArg(args, "dry_run")
		return b.client.RerunRun(ctx, runID, fromStep, dryRun)
	case "cordum.workflow.cancel":
		workflowID := stringArg(args, "workflow_id")
		runID := stringArg(args, "run_id")
		if workflowID == "" || runID == "" {
			return nil, fmt.Errorf("workflow_id and run_id required")
		}
		return b.client.CancelRun(ctx, workflowID, runID)
	case "cordum.job.approve":
		jobID := stringArg(args, "job_id")
		if jobID == "" {
			return nil, fmt.Errorf("job_id required")
		}
		reason := stringArg(args, "reason")
		note := stringArg(args, "note")
		return b.client.ApproveJob(ctx, jobID, reason, note)
	case "cordum.job.reject":
		jobID := stringArg(args, "job_id")
		if jobID == "" {
			return nil, fmt.Errorf("job_id required")
		}
		reason := stringArg(args, "reason")
		note := stringArg(args, "note")
		return b.client.RejectJob(ctx, jobID, reason, note)
	case "cordum.job.remediate":
		jobID := stringArg(args, "job_id")
		if jobID == "" {
			return nil, fmt.Errorf("job_id required")
		}
		remediationID := stringArg(args, "remediation_id")
		return b.client.RemediateJob(ctx, jobID, remediationID)
	case "cordum.job.cancel":
		jobID := stringArg(args, "job_id")
		if jobID == "" {
			return nil, fmt.Errorf("job_id required")
		}
		return b.client.CancelJob(ctx, jobID)
	case "cordum.dlq.retry":
		jobID := stringArg(args, "job_id")
		if jobID == "" {
			return nil, fmt.Errorf("job_id required")
		}
		return b.client.RetryDLQ(ctx, jobID)
	default:
		return nil, fmt.Errorf("unsupported tool: %s", name)
	}
}

func (b *Bridge) readResource(ctx context.Context, uri string) (mcp.ResourceContent, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return mcp.ResourceContent{}, err
	}
	if parsed.Scheme != "cordum" {
		return mcp.ResourceContent{}, fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}
	pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	switch parsed.Host {
	case "jobs":
		if len(pathParts) == 0 || pathParts[0] == "" {
			return mcp.ResourceContent{}, fmt.Errorf("job id required")
		}
		jobID := pathParts[0]
		if len(pathParts) > 1 && pathParts[1] == "decisions" {
			decisions, err := b.client.GetJobDecisions(ctx, jobID)
			if err != nil {
				return mcp.ResourceContent{}, err
			}
			return jsonContent(uri, decisions), nil
		}
		job, err := b.client.GetJob(ctx, jobID)
		if err != nil {
			return mcp.ResourceContent{}, err
		}
		return jsonContent(uri, job), nil
	case "runs":
		if len(pathParts) == 0 || pathParts[0] == "" {
			return mcp.ResourceContent{}, fmt.Errorf("run id required")
		}
		runID := pathParts[0]
		if len(pathParts) > 1 && pathParts[1] == "timeline" {
			timeline, err := b.client.GetRunTimeline(ctx, runID)
			if err != nil {
				return mcp.ResourceContent{}, err
			}
			return jsonContent(uri, timeline), nil
		}
		run, err := b.client.GetRun(ctx, runID)
		if err != nil {
			return mcp.ResourceContent{}, err
		}
		return jsonContent(uri, run), nil
	case "artifacts":
		if len(pathParts) == 0 || pathParts[0] == "" {
			return mcp.ResourceContent{}, fmt.Errorf("artifact ptr required")
		}
		ptr, _ := url.PathUnescape(strings.Join(pathParts, "/"))
		artifact, err := b.client.GetArtifact(ctx, ptr)
		if err != nil {
			return mcp.ResourceContent{}, err
		}
		contentBytes, err := artifact.ContentBytes()
		if err != nil {
			return mcp.ResourceContent{}, err
		}
		if isText(contentBytes) {
			return mcp.ResourceContent{URI: uri, MimeType: artifact.Metadata.ContentType, Text: string(contentBytes)}, nil
		}
		return mcp.ResourceContent{URI: uri, MimeType: artifact.Metadata.ContentType, Blob: base64.StdEncoding.EncodeToString(contentBytes)}, nil
	case "memory":
		ptr := parsed.Query().Get("ptr")
		if ptr == "" {
			return mcp.ResourceContent{}, fmt.Errorf("ptr query required")
		}
		mem, err := b.client.GetMemory(ctx, ptr)
		if err != nil {
			return mcp.ResourceContent{}, err
		}
		return jsonContent(uri, mem), nil
	default:
		return mcp.ResourceContent{}, fmt.Errorf("unsupported resource: %s", parsed.Host)
	}
}

func jsonContent(uri string, value any) mcp.ResourceContent {
	payload, _ := json.MarshalIndent(value, "", "  ")
	return mcp.ResourceContent{
		URI:      uri,
		MimeType: "application/json",
		Text:     string(payload),
	}
}

func isText(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return false
		}
	}
	return true
}

func stringArg(args map[string]any, key string) string {
	if val, ok := args[key]; ok {
		switch v := val.(type) {
		case string:
			return strings.TrimSpace(v)
		case fmt.Stringer:
			return strings.TrimSpace(v.String())
		default:
			return strings.TrimSpace(fmt.Sprint(v))
		}
	}
	return ""
}

func boolArg(args map[string]any, key string) bool {
	if val, ok := args[key]; ok {
		switch v := val.(type) {
		case bool:
			return v
		case string:
			return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
		}
	}
	return false
}

func buildJobRequest(toolName string, args map[string]any, cfg Config) jobSubmitRequest {
	riskTags := toolRiskTags(toolName)
	labels := map[string]string{
		"mcp.server": cfg.ServerName,
		"mcp.tool":   toolName,
		"mcp.action": "call",
	}
	ctx := map[string]any{
		"tool": toolName,
		"args": args,
	}
	return jobSubmitRequest{
		Prompt:      fmt.Sprintf("mcp tool call: %s", toolName),
		Topic:       cfg.JobTopic,
		Context:     ctx,
		Capability:  toolName,
		RiskTags:    riskTags,
		Requires:    []string{"network:egress"},
		PackID:      cfg.PackID,
		Labels:      labels,
		ActorID:     "mcp-bridge",
		ActorType:   "service",
		PrincipalID: "mcp-bridge",
	}
}

func toolRiskTags(name string) []string {
	switch name {
	case "cordum.workflow.run", "cordum.workflow.rerun", "cordum.workflow.cancel", "cordum.job.approve", "cordum.job.reject", "cordum.job.remediate", "cordum.job.cancel", "cordum.dlq.retry":
		return []string{"write"}
	default:
		return []string{"read"}
	}
}

func (b *Bridge) buildTools() []mcp.Tool {
	return []mcp.Tool{
		{
			Name:        "cordum.workflow.run",
			Description: "Start a workflow run.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"workflow_id":     map[string]any{"type": "string"},
					"input":           map[string]any{"type": "object"},
					"dry_run":         map[string]any{"type": "boolean"},
					"idempotency_key": map[string]any{"type": "string"},
				},
				"required": []string{"workflow_id"},
			},
		},
		{
			Name:        "cordum.workflow.rerun",
			Description: "Replay a workflow run (optionally from a step).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"run_id":    map[string]any{"type": "string"},
					"from_step": map[string]any{"type": "string"},
					"dry_run":   map[string]any{"type": "boolean"},
				},
				"required": []string{"run_id"},
			},
		},
		{
			Name:        "cordum.workflow.cancel",
			Description: "Cancel a running workflow.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"workflow_id": map[string]any{"type": "string"},
					"run_id":      map[string]any{"type": "string"},
				},
				"required": []string{"workflow_id", "run_id"},
			},
		},
		{
			Name:        "cordum.job.approve",
			Description: "Approve a job awaiting policy approval.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"job_id": map[string]any{"type": "string"},
					"reason": map[string]any{"type": "string"},
					"note":   map[string]any{"type": "string"},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "cordum.job.reject",
			Description: "Reject a job awaiting policy approval.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"job_id": map[string]any{"type": "string"},
					"reason": map[string]any{"type": "string"},
					"note":   map[string]any{"type": "string"},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "cordum.job.remediate",
			Description: "Apply a suggested remediation for a denied job.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"job_id":         map[string]any{"type": "string"},
					"remediation_id": map[string]any{"type": "string"},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "cordum.job.cancel",
			Description: "Cancel a queued or running job.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"job_id": map[string]any{"type": "string"},
				},
				"required": []string{"job_id"},
			},
		},
		{
			Name:        "cordum.dlq.retry",
			Description: "Retry a job from the DLQ.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"job_id": map[string]any{"type": "string"},
				},
				"required": []string{"job_id"},
			},
		},
	}
}

func (b *Bridge) buildResourceTemplates() []mcp.ResourceTemplate {
	return []mcp.ResourceTemplate{
		{URITemplate: "cordum://jobs/{job_id}", Name: "Job", Description: "Job details", MimeType: "application/json"},
		{URITemplate: "cordum://jobs/{job_id}/decisions", Name: "Job Decisions", Description: "Safety decision history", MimeType: "application/json"},
		{URITemplate: "cordum://runs/{run_id}", Name: "Run", Description: "Workflow run details", MimeType: "application/json"},
		{URITemplate: "cordum://runs/{run_id}/timeline", Name: "Run Timeline", Description: "Workflow run timeline", MimeType: "application/json"},
		{URITemplate: "cordum://artifacts/{artifact_ptr}", Name: "Artifact", Description: "Artifact payload", MimeType: "application/json"},
		{URITemplate: "cordum://memory?ptr=redis://ctx:<job_id>", Name: "Memory", Description: "Context/result pointers", MimeType: "application/json"},
	}
}

func negotiateProtocolVersion(requested string) (string, error) {
	if requested == "" {
		return defaultProtocolVersion, nil
	}
	for _, version := range supportedProtocolVersions {
		if requested == version {
			return version, nil
		}
	}
	return "", mcp.NewInvalidParamsError(fmt.Sprintf("unsupported protocolVersion %q", requested))
}

type jobSubmitRequest struct {
	Prompt      string            `json:"prompt"`
	Topic       string            `json:"topic"`
	Context     any               `json:"context"`
	Capability  string            `json:"capability"`
	RiskTags    []string          `json:"risk_tags"`
	Requires    []string          `json:"requires"`
	PackID      string            `json:"pack_id"`
	Labels      map[string]string `json:"labels"`
	ActorID     string            `json:"actor_id"`
	ActorType   string            `json:"actor_type"`
	PrincipalID string            `json:"principal_id"`
}

type jobSubmitResponse struct {
	JobID   string `json:"job_id"`
	TraceID string `json:"trace_id"`
}

type gatewayClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func newGatewayClient(baseURL, apiKey string) *gatewayClient {
	return &gatewayClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *gatewayClient) SubmitJob(ctx context.Context, req jobSubmitRequest) (jobSubmitResponse, error) {
	var resp jobSubmitResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/jobs", req, &resp); err != nil {
		return jobSubmitResponse{}, err
	}
	return resp, nil
}

func (c *gatewayClient) StartRun(ctx context.Context, workflowID string, input map[string]any, dryRun bool, idempotencyKey string) (map[string]any, error) {
	path := "/api/v1/workflows/" + url.PathEscape(workflowID) + "/runs"
	if dryRun {
		path += "?dry_run=true"
	}
	headers := map[string]string{}
	if idempotencyKey != "" {
		headers["Idempotency-Key"] = idempotencyKey
	}
	var resp map[string]any
	if err := c.doJSONWithHeaders(ctx, http.MethodPost, path, input, &resp, headers); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) RerunRun(ctx context.Context, runID, fromStep string, dryRun bool) (map[string]any, error) {
	path := "/api/v1/workflow-runs/" + url.PathEscape(runID) + "/rerun"
	body := map[string]any{}
	if fromStep != "" {
		body["from_step"] = fromStep
	}
	if dryRun {
		body["dry_run"] = true
	}
	var resp map[string]any
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) CancelRun(ctx context.Context, workflowID, runID string) (map[string]any, error) {
	path := "/api/v1/workflows/" + url.PathEscape(workflowID) + "/runs/" + url.PathEscape(runID) + "/cancel"
	if err := c.doJSON(ctx, http.MethodPost, path, nil, nil); err != nil {
		return nil, err
	}
	return map[string]any{"status": "cancelled"}, nil
}

func (c *gatewayClient) ApproveJob(ctx context.Context, jobID, reason, note string) (map[string]any, error) {
	path := "/api/v1/approvals/" + url.PathEscape(jobID) + "/approve"
	body := map[string]any{}
	if reason != "" {
		body["reason"] = reason
	}
	if note != "" {
		body["note"] = note
	}
	var resp map[string]any
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) RejectJob(ctx context.Context, jobID, reason, note string) (map[string]any, error) {
	path := "/api/v1/approvals/" + url.PathEscape(jobID) + "/reject"
	body := map[string]any{}
	if reason != "" {
		body["reason"] = reason
	}
	if note != "" {
		body["note"] = note
	}
	var resp map[string]any
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) RemediateJob(ctx context.Context, jobID, remediationID string) (map[string]any, error) {
	path := "/api/v1/jobs/" + url.PathEscape(jobID) + "/remediate"
	body := map[string]any{}
	if remediationID != "" {
		body["remediation_id"] = remediationID
	}
	var resp map[string]any
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) RetryDLQ(ctx context.Context, jobID string) (map[string]any, error) {
	path := "/api/v1/dlq/" + url.PathEscape(jobID) + "/retry"
	var resp map[string]any
	if err := c.doJSON(ctx, http.MethodPost, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) CancelJob(ctx context.Context, jobID string) (map[string]any, error) {
	path := "/api/v1/jobs/" + url.PathEscape(jobID) + "/cancel"
	var resp map[string]any
	if err := c.doJSON(ctx, http.MethodPost, path, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) GetJob(ctx context.Context, jobID string) (*jobDetail, error) {
	var resp jobDetail
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *gatewayClient) GetJobDecisions(ctx context.Context, jobID string) ([]map[string]any, error) {
	var resp []map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(jobID)+"/decisions", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) GetRun(ctx context.Context, runID string) (map[string]any, error) {
	var resp map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/workflow-runs/"+url.PathEscape(runID), nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) GetRunTimeline(ctx context.Context, runID string) ([]map[string]any, error) {
	var resp []map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/workflow-runs/"+url.PathEscape(runID)+"/timeline", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *gatewayClient) GetArtifact(ctx context.Context, ptr string) (*artifactPayload, error) {
	var resp artifactPayload
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/artifacts/"+url.PathEscape(ptr), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *gatewayClient) GetMemory(ctx context.Context, ptr string) (*memoryPayload, error) {
	path := "/api/v1/memory?ptr=" + url.QueryEscape(ptr)
	var resp memoryPayload
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *gatewayClient) doJSON(ctx context.Context, method, path string, body any, out any) error {
	return c.doJSONWithHeaders(ctx, method, path, body, out, nil)
}

func (c *gatewayClient) doJSONWithHeaders(ctx context.Context, method, path string, body any, out any, headers map[string]string) error {
	var payload strings.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = *strings.NewReader(string(data))
	}
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, c.baseURL+path, &payload)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	}
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	for k, v := range headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("gateway error: %s", msg)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type jobDetail struct {
	ID                 string           `json:"id"`
	State              string           `json:"state"`
	Result             any              `json:"result"`
	ErrorMessage       string           `json:"error_message"`
	SafetyReason       string           `json:"safety_reason"`
	ApprovalRequired   bool             `json:"approval_required"`
	ApprovalRef        string           `json:"approval_ref"`
	SafetyRemediations []map[string]any `json:"safety_remediations"`
}

func (j *jobDetail) IsTerminal() bool {
	state := strings.ToUpper(j.State)
	switch state {
	case "SUCCEEDED", "FAILED", "DENIED", "CANCELLED", "TIMEOUT":
		return true
	case "APPROVAL_REQUIRED":
		return true
	default:
		return false
	}
}

func (j *jobDetail) AsResult() any {
	out := map[string]any{
		"job_id":  j.ID,
		"state":   j.State,
		"job_uri": fmt.Sprintf("cordum://jobs/%s", j.ID),
	}
	if j.Result != nil {
		out["result"] = j.Result
	}
	if j.ApprovalRequired {
		out["approval_required"] = true
		out["approval_ref"] = j.ApprovalRef
		out["remediations"] = j.SafetyRemediations
		out["decisions_uri"] = fmt.Sprintf("cordum://jobs/%s/decisions", j.ID)
	}
	if j.SafetyReason != "" {
		out["reason"] = j.SafetyReason
	}
	return out
}

func (j *jobDetail) AsError() error {
	state := strings.ToUpper(j.State)
	switch state {
	case "APPROVAL_REQUIRED":
		return fmt.Errorf("approval required")
	case "DENIED":
		if j.SafetyReason != "" {
			return fmt.Errorf("denied: %s", j.SafetyReason)
		}
		return fmt.Errorf("denied")
	case "FAILED", "CANCELLED", "TIMEOUT":
		if j.ErrorMessage != "" {
			return errors.New(j.ErrorMessage)
		}
		return fmt.Errorf("job %s", strings.ToLower(state))
	default:
		return nil
	}
}

type artifactPayload struct {
	Pointer  string `json:"artifact_ptr"`
	Content  string `json:"content_base64"`
	Metadata struct {
		ContentType string `json:"content_type"`
	} `json:"metadata"`
}

type memoryPayload struct {
	Pointer string `json:"pointer"`
	JSON    any    `json:"json"`
}

func (a *artifactPayload) ContentBytes() ([]byte, error) {
	if a.Content == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(a.Content)
}

func (c *gatewayClient) GetArtifactContent(ctx context.Context, ptr string) ([]byte, string, error) {
	artifact, err := c.GetArtifact(ctx, ptr)
	if err != nil {
		return nil, "", err
	}
	data, err := artifact.ContentBytes()
	return data, artifact.Metadata.ContentType, err
}
