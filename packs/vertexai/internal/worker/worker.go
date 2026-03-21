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
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/config"
	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/services"
	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/vertexclient"
)

const (
	topicRead     = "job.vertexai.read"
	topicGenerate = "job.vertexai.generate"
	topicWrite    = "job.vertexai.write"
)

const (
	actionPredict         = "predict.predict"
	actionRawPredict      = "predict.raw_predict"
	actionCreateBatchJob  = "batch.create_prediction_job"
	actionGetBatchJob     = "batch.get_prediction_job"
	actionListBatchJobs   = "batch.list_prediction_jobs"
	actionGenerateContent = "generate.generate_content"
	actionEmbedContent    = "embed.embed_content"
	actionCreatePipeline  = "training.create_pipeline"
	actionGetPipeline     = "training.get_pipeline"
	actionListPipelines   = "training.list_pipelines"
)

type actionSpec struct {
	Topic         string
	Intent        string
	Service       string
	ModelRequired bool
}

var actionSpecs = map[string]actionSpec{
	actionPredict:         {Topic: topicRead, Intent: "read", Service: "predict"},
	actionRawPredict:      {Topic: topicRead, Intent: "read", Service: "predict"},
	actionCreateBatchJob:  {Topic: topicWrite, Intent: "write", Service: "batch", ModelRequired: true},
	actionGetBatchJob:     {Topic: topicWrite, Intent: "write", Service: "batch"},
	actionListBatchJobs:   {Topic: topicWrite, Intent: "write", Service: "batch"},
	actionGenerateContent: {Topic: topicGenerate, Intent: "generate", Service: "generate", ModelRequired: true},
	actionEmbedContent:    {Topic: topicRead, Intent: "read", Service: "embed", ModelRequired: true},
	actionCreatePipeline:  {Topic: topicWrite, Intent: "write", Service: "training"},
	actionGetPipeline:     {Topic: topicWrite, Intent: "write", Service: "training"},
	actionListPipelines:   {Topic: topicWrite, Intent: "write", Service: "training"},
}

type dispatchFunc func(ctx context.Context, reqCfg vertexclient.RequestConfig, action string, spec actionSpec, params map[string]any) (any, error)

// Worker handles Vertex AI pack jobs.
type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
	dispatch dispatchFunc
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
	JobID        string         `json:"job_id"`
	Profile      string         `json:"profile,omitempty"`
	Action       string         `json:"action"`
	ProjectID    string         `json:"project_id,omitempty"`
	Location     string         `json:"location,omitempty"`
	StatusCode   int            `json:"status_code"`
	RequestID    string         `json:"request_id,omitempty"`
	DurationMs   int64          `json:"duration_ms,omitempty"`
	LatencyMs    int64          `json:"latency_ms,omitempty"`
	Result       any            `json:"result,omitempty"`
	Error        string         `json:"error,omitempty"`
	Candidates   []any          `json:"candidates,omitempty"`
	FinishReason string         `json:"finish_reason,omitempty"`
	TokenUsage   *TokenUsage    `json:"token_usage,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// New creates a new Vertex AI worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "vertexai")
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
		dispatch: dispatchAction,
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
		subjects = []string{topicRead, topicGenerate, topicWrite}
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

	slog.Info("vertexai worker started", "worker_id", w.workerID, "subjects", subjects)

	<-ctx.Done()
	return ctx.Err()
}

func (w *Worker) handleJob(rctx runtime.Context, payload map[string]any) (jobResult JobResult, err error) {
	if w.sem != nil {
		w.sem <- struct{}{}
	}
	atomic.AddInt32(&w.active, 1)
	defer func() {
		if w.sem != nil {
			<-w.sem
		}
		atomic.AddInt32(&w.active, -1)
	}()

	start := time.Now()
	jobID := ""
	topic := ""
	if rctx.Job != nil {
		jobID = rctx.Job.GetJobId()
		topic = rctx.Job.GetTopic()
	}

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

	jobResult = JobResult{
		JobID:      jobID,
		Action:     action,
		RequestID:  input.RequestID,
		DurationMs: 0,
		LatencyMs:  0,
		Metadata: map[string]any{
			"service": spec.Service,
			"intent":  spec.Intent,
			"topic":   firstNonEmpty(topic, spec.Topic),
		},
	}
	defer func() {
		duration := time.Since(start).Milliseconds()
		jobResult.DurationMs = duration
		jobResult.LatencyMs = duration
	}()

	if err := w.enforceTopic(topic, spec); err != nil {
		jobResult.Error = err.Error()
		return jobResult, nil
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}
	if err := validateActionInput(action, params); err != nil {
		jobResult.Error = err.Error()
		return jobResult, nil
	}

	reqCfg, err := vertexclient.ResolveRequestConfig(ctx, w.cfg, input.Profile, input.ProjectID, input.Location)
	if err != nil {
		jobResult.ProjectID = strings.TrimSpace(input.ProjectID)
		jobResult.Location = strings.TrimSpace(input.Location)
		jobResult.Error = fmt.Sprintf("vertex config: %v", err)
		return jobResult, nil
	}
	jobResult.Profile = reqCfg.Profile.Name
	jobResult.ProjectID = reqCfg.ProjectID
	jobResult.Location = reqCfg.Location
	jobResult.Metadata["max_tokens_per_request"] = reqCfg.MaxTokensPerRequest

	if model := strings.TrimSpace(stringValue(params["model"])); model != "" {
		jobResult.Metadata["model"] = model
		if !reqCfg.Profile.IsModelAllowed(model) {
			jobResult.Error = fmt.Sprintf("model %q is not allowed by profile %q", model, reqCfg.Profile.Name)
			return jobResult, nil
		}
	}
	if err := enforceTokenLimit(params, reqCfg.MaxTokensPerRequest); err != nil {
		jobResult.Error = err.Error()
		return jobResult, nil
	}

	result, err := w.dispatch(ctx, reqCfg, action, spec, params)
	if err != nil {
		jobResult.Error = normalizeVertexError(err)
		return jobResult, nil
	}

	jobResult.StatusCode = 200
	jobResult.Result = result
	jobResult.TokenUsage, jobResult.Candidates, jobResult.FinishReason = extractResultMetadata(result)
	if jobResult.TokenUsage == nil {
		delete(jobResult.Metadata, "max_tokens_per_request")
	}

	slog.Info("vertexai job completed",
		"job_id", jobID,
		"action", action,
		"service", spec.Service,
		"project_id", jobResult.ProjectID,
		"location", jobResult.Location,
		"duration_ms", time.Since(start).Milliseconds(),
		"error", jobResult.Error,
	)

	return jobResult, nil
}

func (w *Worker) enforceTopic(topic string, spec actionSpec) error {
	if strings.TrimSpace(topic) == "" {
		return fmt.Errorf("job topic missing")
	}
	if topic != spec.Topic {
		return fmt.Errorf("%s actions must use %s topic", spec.Intent, spec.Topic)
	}
	return nil
}

func dispatchAction(ctx context.Context, reqCfg vertexclient.RequestConfig, action string, spec actionSpec, params map[string]any) (any, error) {
	switch spec.Service {
	case "predict":
		svc, err := services.NewPredictService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case actionPredict:
			return svc.Predict(ctx, params)
		case actionRawPredict:
			return svc.RawPredict(ctx, params)
		}

	case "batch":
		svc, err := services.NewBatchService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case actionCreateBatchJob:
			return svc.CreatePredictionJob(ctx, params)
		case actionGetBatchJob:
			return svc.GetPredictionJob(ctx, params)
		case actionListBatchJobs:
			return svc.ListPredictionJobs(ctx, params)
		}

	case "generate":
		svc, err := services.NewGenerateService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()
		return svc.GenerateContent(ctx, params)

	case "embed":
		svc, err := services.NewEmbedService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()
		return svc.EmbedContent(ctx, params)

	case "training":
		svc, err := services.NewTrainingService(ctx, reqCfg)
		if err != nil {
			return nil, err
		}
		defer svc.Close()

		switch action {
		case actionCreatePipeline:
			return svc.CreatePipeline(ctx, params)
		case actionGetPipeline:
			return svc.GetPipeline(ctx, params)
		case actionListPipelines:
			return svc.ListPipelines(ctx, params)
		}
	}

	return nil, fmt.Errorf("unhandled action: %s", action)
}

func validateActionInput(action string, params map[string]any) error {
	switch action {
	case actionPredict:
		if strings.TrimSpace(stringValue(params["endpoint_id"])) == "" {
			return fmt.Errorf("endpoint_id is required")
		}
		if !hasNonEmptySlice(params["instances"]) {
			return fmt.Errorf("instances are required")
		}
	case actionRawPredict:
		if strings.TrimSpace(stringValue(params["endpoint_id"])) == "" {
			return fmt.Errorf("endpoint_id is required")
		}
		if strings.TrimSpace(stringValue(params["body"])) == "" && !hasNonEmptySlice(params["instances"]) {
			return fmt.Errorf("body or instances is required")
		}
	case actionCreateBatchJob:
		if strings.TrimSpace(stringValue(params["model"])) == "" {
			return fmt.Errorf("model is required")
		}
		if strings.TrimSpace(stringValue(params["input_uri"])) == "" {
			return fmt.Errorf("input_uri is required")
		}
		if strings.TrimSpace(stringValue(params["output_uri"])) == "" {
			return fmt.Errorf("output_uri is required")
		}
	case actionGetBatchJob:
		if strings.TrimSpace(firstNonEmpty(stringValue(params["job_id"]), stringValue(params["name"]))) == "" {
			return fmt.Errorf("job_id or name is required")
		}
	case actionGenerateContent:
		if strings.TrimSpace(stringValue(params["model"])) == "" {
			return fmt.Errorf("model is required")
		}
		if strings.TrimSpace(stringValue(params["prompt"])) == "" && !hasNonEmptySlice(params["messages"]) {
			return fmt.Errorf("prompt or messages is required")
		}
	case actionEmbedContent:
		if strings.TrimSpace(stringValue(params["model"])) == "" {
			return fmt.Errorf("model is required")
		}
		if !hasNonEmptySlice(params["contents"]) {
			return fmt.Errorf("contents are required")
		}
	case actionCreatePipeline:
		if strings.TrimSpace(stringValue(params["training_task_definition"])) == "" {
			return fmt.Errorf("training_task_definition is required")
		}
		if params["training_task_inputs"] == nil && params["task_inputs"] == nil {
			return fmt.Errorf("training_task_inputs is required")
		}
	case actionGetPipeline:
		if strings.TrimSpace(firstNonEmpty(stringValue(params["pipeline_id"]), stringValue(params["name"]))) == "" {
			return fmt.Errorf("pipeline_id or name is required")
		}
	}
	return nil
}

func enforceTokenLimit(params map[string]any, maxTokensPerRequest int) error {
	if maxTokensPerRequest <= 0 || params == nil {
		return nil
	}
	rawConfig, ok := params["generation_config"].(map[string]any)
	if !ok || rawConfig == nil {
		return nil
	}
	value, ok := rawConfig["max_tokens"]
	if !ok || value == nil {
		return nil
	}
	maxTokens, err := intValue(value)
	if err != nil {
		return fmt.Errorf("generation_config.max_tokens must be numeric")
	}
	if maxTokens > maxTokensPerRequest {
		return fmt.Errorf("generation_config.max_tokens exceeds configured limit of %d", maxTokensPerRequest)
	}
	return nil
}

func extractResultMetadata(result any) (*TokenUsage, []any, string) {
	mapped, ok := result.(map[string]any)
	if !ok {
		return nil, nil, ""
	}

	var usage *TokenUsage
	if tokenUsageMap, ok := mapped["token_usage"].(map[string]any); ok {
		candidate := TokenUsage{
			PromptTokens:     numericValue(tokenUsageMap["prompt_tokens"]),
			CompletionTokens: numericValue(tokenUsageMap["completion_tokens"]),
			TotalTokens:      numericValue(tokenUsageMap["total_tokens"]),
		}
		if candidate != (TokenUsage{}) {
			usage = &candidate
		}
	}

	candidates, _ := mapped["candidates"].([]any)
	finishReason := strings.TrimSpace(stringValue(mapped["finish_reason"]))
	if finishReason == "" && len(candidates) > 0 {
		if first, ok := candidates[0].(map[string]any); ok {
			finishReason = strings.TrimSpace(stringValue(first["finish_reason"]))
		}
	}
	return usage, candidates, finishReason
}

func normalizeVertexError(err error) string {
	if err == nil {
		return ""
	}
	if status, ok := grpcstatus.FromError(err); ok {
		switch status.Code() {
		case codes.NotFound:
			return fmt.Sprintf("vertex resource not found: %s", status.Message())
		case codes.PermissionDenied:
			return fmt.Sprintf("vertex permission denied: %s", status.Message())
		case codes.Unauthenticated:
			return fmt.Sprintf("vertex authentication failed: %s", status.Message())
		case codes.ResourceExhausted:
			return fmt.Sprintf("vertex quota exhausted or rate limited: %s", status.Message())
		case codes.DeadlineExceeded:
			return fmt.Sprintf("vertex request timed out: %s", status.Message())
		case codes.InvalidArgument:
			return fmt.Sprintf("vertex request invalid: %s", status.Message())
		}
	}
	return err.Error()
}

func hasNonEmptySlice(value any) bool {
	switch typed := value.(type) {
	case []any:
		return len(typed) > 0
	case []string:
		return len(typed) > 0
	default:
		return false
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprint(value)
	}
}

func intValue(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int32:
		return int(typed), nil
	case int64:
		return int(typed), nil
	case float64:
		if float64(int(typed)) != typed {
			return 0, fmt.Errorf("not a whole number")
		}
		return int(typed), nil
	case float32:
		if float32(int(typed)) != typed {
			return 0, fmt.Errorf("not a whole number")
		}
		return int(typed), nil
	default:
		return 0, fmt.Errorf("not numeric")
	}
}

func numericValue(value any) int {
	parsed, err := intValue(value)
	if err != nil {
		return 0
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
