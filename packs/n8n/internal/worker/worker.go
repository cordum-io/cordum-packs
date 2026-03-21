package worker

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/n8n/internal/config"
	"github.com/cordum-io/cordum-packs/packs/n8n/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/n8n/internal/n8napi"
	"github.com/cordum-io/cordum-packs/packs/n8n/internal/webhook"
)

const (
	topicRead  = "job.n8n.read"
	topicWrite = "job.n8n.write"
)

const (
	actionWorkflowList       = "workflow.list"
	actionWorkflowGet        = "workflow.get"
	actionWorkflowExecute    = "workflow.execute"
	actionWorkflowActivate   = "workflow.activate"
	actionWorkflowDeactivate = "workflow.deactivate"
	actionExecutionGet       = "execution.get"
	actionExecutionList      = "execution.list"
	actionCredentialsList    = "credentials.list"
)

type actionSpec struct {
	Topic         string
	Intent        string
	WorkflowParam string
}

var actionSpecs = map[string]actionSpec{
	actionWorkflowList:       {Topic: topicRead, Intent: "read"},
	actionWorkflowGet:        {Topic: topicRead, Intent: "read", WorkflowParam: "workflow_id"},
	actionWorkflowExecute:    {Topic: topicWrite, Intent: "write", WorkflowParam: "workflow_id"},
	actionWorkflowActivate:   {Topic: topicWrite, Intent: "write", WorkflowParam: "workflow_id"},
	actionWorkflowDeactivate: {Topic: topicWrite, Intent: "write", WorkflowParam: "workflow_id"},
	actionExecutionGet:       {Topic: topicRead, Intent: "read"},
	actionExecutionList:      {Topic: topicRead, Intent: "read"},
	actionCredentialsList:    {Topic: topicRead, Intent: "read"},
}

type n8nClient interface {
	ListWorkflows(ctx context.Context, params map[string]any) (map[string]any, error)
	GetWorkflow(ctx context.Context, workflowID string) (map[string]any, error)
	ExecuteWorkflow(ctx context.Context, workflowID string, payload map[string]any) (map[string]any, error)
	GetExecution(ctx context.Context, executionID string, includeData bool) (map[string]any, error)
	ListExecutions(ctx context.Context, params map[string]any) (map[string]any, error)
	ActivateWorkflow(ctx context.Context, workflowID string) (map[string]any, error)
	DeactivateWorkflow(ctx context.Context, workflowID string) (map[string]any, error)
	ListCredentials(ctx context.Context) (map[string]any, error)
}

type clientFactory func(profile config.Profile, timeout time.Duration) (n8nClient, error)

// Worker handles n8n pack jobs.
type Worker struct {
	cfg       config.Config
	agent     *runtime.Agent
	natsConn  *nats.Conn
	workerID  string
	sem       chan struct{}
	active    int32
	newClient clientFactory
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
	JobID       string         `json:"job_id"`
	Profile     string         `json:"profile,omitempty"`
	Action      string         `json:"action"`
	WorkflowID  string         `json:"workflow_id,omitempty"`
	ExecutionID string         `json:"execution_id,omitempty"`
	RequestID   string         `json:"request_id,omitempty"`
	StatusCode  int            `json:"status_code"`
	Status      string         `json:"status,omitempty"`
	DurationMs  int64          `json:"duration_ms,omitempty"`
	Result      any            `json:"result,omitempty"`
	Error       string         `json:"error,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// New creates a new n8n worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "n8n")
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
	w.newClient = func(profile config.Profile, timeout time.Duration) (n8nClient, error) {
		return n8napi.NewClient(profile.BaseURL, profile.ResolveAPIKey(), timeout)
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
	if w.cfg.WebhookEnabled {
		gateway := gatewayclient.New(w.cfg.GatewayURL, w.cfg.APIKey, w.cfg.TenantID)
		server := webhook.New(w.cfg, gateway)
		go func() {
			if err := server.ListenAndServe(ctx); err != nil {
				slog.Error("n8n webhook server stopped", "error", err)
			}
		}()
	}

	slog.Info("n8n worker started", "worker_id", w.workerID, "subjects", subjects, "webhook_enabled", w.cfg.WebhookEnabled)
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
		Metadata:   map[string]any{"topic": firstNonEmpty(topic, spec.Topic), "intent": spec.Intent},
		DurationMs: 0,
	}
	defer func() { jobResult.DurationMs = time.Since(start).Milliseconds() }()

	if err := enforceTopic(topic, spec); err != nil {
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

	profile := w.cfg.ResolveProfile(input.Profile)
	if profile.Name == "" {
		profile.Name = w.cfg.DefaultProfile
	}
	jobResult.Profile = profile.Name
	if workflowID := workflowIDFromParams(params); workflowID != "" {
		jobResult.WorkflowID = workflowID
		if !profile.IsWorkflowAllowed(workflowID) {
			jobResult.Error = fmt.Sprintf("workflow %q is not allowed by profile %q", workflowID, profile.Name)
			return jobResult, nil
		}
	}
	client, err := w.newClient(profile, w.requestTimeout(action, params))
	if err != nil {
		jobResult.Error = fmt.Sprintf("n8n client: %v", err)
		return jobResult, nil
	}

	callCtx, cancel := context.WithTimeout(context.Background(), w.requestTimeout(action, params))
	defer cancel()
	result, execErr := w.execute(callCtx, client, action, params)
	if execErr != nil {
		jobResult.Error = execErr.Error()
		return jobResult, nil
	}

	jobResult.StatusCode = 200
	jobResult.Result = result
	jobResult.WorkflowID = firstNonEmpty(jobResult.WorkflowID, workflowIDFromResult(result))
	jobResult.ExecutionID = executionIDFromResult(result)
	jobResult.Status = statusFromResult(result)
	return jobResult, nil
}

func (w *Worker) execute(ctx context.Context, client n8nClient, action string, params map[string]any) (map[string]any, error) {
	switch action {
	case actionWorkflowList:
		result, err := client.ListWorkflows(ctx, params)
		if err != nil {
			return nil, err
		}
		return filterWorkflowList(w.cfg.ResolveProfile(""), result), nil
	case actionWorkflowGet:
		return client.GetWorkflow(ctx, workflowIDFromParams(params))
	case actionWorkflowExecute:
		workflowID := workflowIDFromParams(params)
		payload, _ := params["payload"].(map[string]any)
		result, err := client.ExecuteWorkflow(ctx, workflowID, payload)
		if err != nil {
			return nil, err
		}
		if waitForCompletion(params) {
			executionID := executionIDFromResult(result)
			if executionID == "" {
				return nil, fmt.Errorf("execution response missing execution id")
			}
			return w.waitForExecution(ctx, client, executionID)
		}
		return result, nil
	case actionWorkflowActivate:
		return client.ActivateWorkflow(ctx, workflowIDFromParams(params))
	case actionWorkflowDeactivate:
		return client.DeactivateWorkflow(ctx, workflowIDFromParams(params))
	case actionExecutionGet:
		return client.GetExecution(ctx, firstNonEmpty(stringParam(params, "execution_id"), stringParam(params, "id")), boolParam(params, "include_data", false))
	case actionExecutionList:
		query := map[string]any{}
		for _, key := range []string{"workflowId", "status", "cursor"} {
			if value := strings.TrimSpace(stringValue(params[key])); value != "" {
				query[key] = value
			}
		}
		if value := strings.TrimSpace(stringValue(params["workflow_id"])); value != "" {
			query["workflowId"] = value
		}
		if limit := intValue(params["limit"]); limit > 0 {
			query["limit"] = limit
		}
		if includeData, ok := params["include_data"].(bool); ok {
			query["includeData"] = includeData
		}
		return client.ListExecutions(ctx, query)
	case actionCredentialsList:
		return client.ListCredentials(ctx)
	default:
		return nil, fmt.Errorf("unhandled action: %s", action)
	}
}

func (w *Worker) waitForExecution(ctx context.Context, client n8nClient, executionID string) (map[string]any, error) {
	ticker := time.NewTicker(w.cfg.ExecutePollInterval)
	defer ticker.Stop()
	for {
		result, err := client.GetExecution(ctx, executionID, true)
		if err != nil {
			return nil, err
		}
		if isTerminalExecution(result) {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func enforceTopic(topic string, spec actionSpec) error {
	if strings.TrimSpace(topic) == "" {
		return fmt.Errorf("job topic missing")
	}
	if topic != spec.Topic {
		return fmt.Errorf("%s actions must use %s topic", spec.Intent, spec.Topic)
	}
	return nil
}

func validateActionInput(action string, params map[string]any) error {
	switch action {
	case actionWorkflowGet, actionWorkflowExecute, actionWorkflowActivate, actionWorkflowDeactivate:
		if workflowIDFromParams(params) == "" {
			return fmt.Errorf("workflow_id is required")
		}
	case actionExecutionGet:
		if firstNonEmpty(stringParam(params, "execution_id"), stringParam(params, "id")) == "" {
			return fmt.Errorf("execution_id is required")
		}
	}
	return nil
}

func workflowIDFromParams(params map[string]any) string {
	return firstNonEmpty(stringParam(params, "workflow_id"), stringParam(params, "id"))
}

func workflowIDFromResult(result map[string]any) string {
	if result == nil {
		return ""
	}
	return firstNonEmpty(stringValue(result["workflow_id"]), stringValue(result["workflowId"]), stringValue(result["id"]))
}

func executionIDFromResult(result map[string]any) string {
	if result == nil {
		return ""
	}
	return firstNonEmpty(
		stringValue(result["execution_id"]),
		stringValue(result["executionId"]),
		stringValue(result["id"]),
		lookupNestedString(result, "data", "executionId"),
		lookupNestedString(result, "data", "id"),
	)
}

func statusFromResult(result map[string]any) string {
	if result == nil {
		return ""
	}
	if status := firstNonEmpty(stringValue(result["status"]), lookupNestedString(result, "data", "status")); status != "" {
		return status
	}
	if active, ok := result["active"].(bool); ok {
		if active {
			return "active"
		}
		return "inactive"
	}
	return ""
}

func isTerminalExecution(result map[string]any) bool {
	status := strings.ToLower(statusFromResult(result))
	switch status {
	case "success", "error", "failed", "cancelled", "canceled", "crashed":
		return true
	}
	if finished, ok := result["finished"].(bool); ok && finished {
		return true
	}
	if stoppedAt := firstNonEmpty(stringValue(result["stoppedAt"]), stringValue(result["stopped_at"])); stoppedAt != "" {
		return true
	}
	return false
}

func waitForCompletion(params map[string]any) bool {
	if params == nil {
		return false
	}
	return boolParam(params, "wait_for_completion", false)
}

func (w *Worker) requestTimeout(action string, params map[string]any) time.Duration {
	timeout := w.cfg.RequestTimeout
	if action == actionWorkflowExecute && waitForCompletion(params) && w.cfg.ExecuteWaitTimeout > timeout {
		return w.cfg.ExecuteWaitTimeout
	}
	return timeout
}

func filterWorkflowList(profile config.Profile, result map[string]any) map[string]any {
	if result == nil || (len(profile.AllowedWorkflows) == 0 && len(profile.DeniedWorkflows) == 0) {
		return result
	}
	items, ok := result["data"].([]any)
	if !ok {
		return result
	}
	filtered := make([]any, 0, len(items))
	for _, item := range items {
		mapped, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		candidate := firstNonEmpty(stringValue(mapped["id"]), stringValue(mapped["name"]))
		if candidate == "" || profile.IsWorkflowAllowed(candidate) {
			filtered = append(filtered, item)
		}
	}
	result["data"] = filtered
	return result
}

func stringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	return strings.TrimSpace(stringValue(params[key]))
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func boolParam(params map[string]any, key string, fallback bool) bool {
	if params == nil {
		return fallback
	}
	value, ok := params[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return fallback
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func lookupNestedString(mapped map[string]any, first, second string) string {
	nested, ok := mapped[first].(map[string]any)
	if !ok {
		return ""
	}
	return stringValue(nested[second])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func matchGlob(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == value {
		return true
	}
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}
