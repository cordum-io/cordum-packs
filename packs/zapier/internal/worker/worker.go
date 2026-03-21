package worker

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/zapier/internal/config"
	"github.com/cordum-io/cordum-packs/packs/zapier/internal/zapierapi"
)

const (
	topicRead  = "job.zapier.read"
	topicWrite = "job.zapier.write"
)

const (
	actionNLAList     = "nla.list"
	actionNLAExecute  = "nla.execute"
	actionNLAPreview  = "nla.preview"
	actionNLALog      = "nla.log"
	actionWebhookSend = "webhook.send"
)

type actionSpec struct {
	Topic  string
	Intent string
}

var actionSpecs = map[string]actionSpec{
	actionNLAList:     {Topic: topicRead, Intent: "read"},
	actionNLALog:      {Topic: topicRead, Intent: "read"},
	actionWebhookSend: {Topic: topicRead, Intent: "read"},
	actionNLAExecute:  {Topic: topicWrite, Intent: "write"},
	actionNLAPreview:  {Topic: topicWrite, Intent: "write"},
}

type nlaClient interface {
	ListActions(ctx context.Context, params map[string]any) (map[string]any, error)
	ExecuteAction(ctx context.Context, req zapierapi.ExecuteRequest) (map[string]any, error)
	GetExecutionLog(ctx context.Context, executionLogID string) (map[string]any, error)
}

type webhookClient interface {
	Send(ctx context.Context, name string, payload map[string]any) (zapierapi.WebhookResponse, error)
}

// Worker handles Zapier pack jobs.
type Worker struct {
	cfg              config.Config
	agent            *runtime.Agent
	natsConn         *nats.Conn
	workerID         string
	sem              chan struct{}
	active           int32
	newNLAClient     func(timeout time.Duration) (nlaClient, error)
	newWebhookClient func(timeout time.Duration) webhookClient
}

// JobInput is the incoming job payload.
type JobInput struct {
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
}

// JobResult is the output payload.
type JobResult struct {
	JobID             string         `json:"job_id"`
	Action            string         `json:"action"`
	RequestID         string         `json:"request_id,omitempty"`
	StatusCode        int            `json:"status_code"`
	Status            string         `json:"status,omitempty"`
	DurationMs        int64          `json:"duration_ms,omitempty"`
	ActionUsed        string         `json:"action_used,omitempty"`
	ExecutionLogID    string         `json:"execution_log_id,omitempty"`
	Result            any            `json:"result,omitempty"`
	AdditionalResults []any          `json:"additional_results,omitempty"`
	Error             string         `json:"error,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

// New creates a new Zapier worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "zapier")
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
	w.newNLAClient = func(timeout time.Duration) (nlaClient, error) {
		return zapierapi.NewClient(cfg.NLABaseURL, cfg.NLAAPIKey, timeout)
	}
	w.newWebhookClient = func(timeout time.Duration) webhookClient {
		return zapierapi.NewWebhookClient(cfg.WebhookURLs, timeout)
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

	slog.Info("zapier worker started", "worker_id", w.workerID, "subjects", subjects, "webhook_aliases", len(w.cfg.WebhookURLs), "nla_configured", w.cfg.HasNLA())
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
		StatusCode: 0,
		Metadata: map[string]any{
			"topic":  firstNonEmpty(topic, spec.Topic),
			"intent": spec.Intent,
		},
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

	callCtx, cancel := context.WithTimeout(context.Background(), w.cfg.RequestTimeout)
	defer cancel()

	var result map[string]any
	switch action {
	case actionWebhookSend:
		result, err = w.handleWebhook(callCtx, params)
	case actionNLAList, actionNLALog, actionNLAExecute, actionNLAPreview:
		result, err = w.handleNLA(callCtx, action, params)
	default:
		err = fmt.Errorf("unhandled action: %s", action)
	}
	if err != nil {
		jobResult.Error = err.Error()
		return jobResult, nil
	}

	jobResult.StatusCode = statusCodeFromResult(result, 200)
	jobResult.Status = statusFromResult(result)
	jobResult.ActionUsed = actionUsedFromResult(result)
	jobResult.ExecutionLogID = executionLogIDFromResult(result)
	jobResult.AdditionalResults = additionalResultsFromResult(result)
	jobResult.Result = result
	return jobResult, nil
}

func (w *Worker) handleWebhook(ctx context.Context, params map[string]any) (map[string]any, error) {
	webhookName := stringParam(params, "webhook_name")
	if !w.cfg.IsWebhookAllowed(webhookName) {
		return nil, fmt.Errorf("webhook %q is not allowed", webhookName)
	}
	resolvedURL, ok := w.cfg.ResolveWebhookURL(webhookName)
	if !ok {
		return nil, fmt.Errorf("webhook %q is not configured", webhookName)
	}
	payload := objectParam(params, "payload")
	client := w.newWebhookClient(w.cfg.RequestTimeout)
	response, err := client.Send(ctx, webhookName, payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"webhook_name": response.Alias,
		"status_code":  response.StatusCode,
		"url":          resolvedURL,
		"response":     response.Body,
		"status":       statusFromHTTP(response.StatusCode),
	}, nil
}

func (w *Worker) handleNLA(ctx context.Context, action string, params map[string]any) (map[string]any, error) {
	if !w.cfg.HasNLA() {
		return nil, fmt.Errorf("NLA API key not configured")
	}
	actionID := stringParam(params, "action_id")
	if requiresPinnedActionID(action, w.cfg) && actionID == "" {
		return nil, fmt.Errorf("action_id is required when action allow/deny rules are configured")
	}
	if actionID != "" && !w.cfg.IsActionAllowed(actionID) {
		return nil, fmt.Errorf("action %q is not allowed", actionID)
	}
	client, err := w.newNLAClient(w.cfg.RequestTimeout)
	if err != nil {
		return nil, fmt.Errorf("zapier AI Actions client: %w", err)
	}
	result, err := w.executeNLA(ctx, client, action, params)
	if err != nil {
		return nil, err
	}
	if action == actionNLAList {
		return filterActionList(w.cfg, result), nil
	}
	return result, nil
}

func (w *Worker) executeNLA(ctx context.Context, client nlaClient, action string, params map[string]any) (map[string]any, error) {
	switch action {
	case actionNLAList:
		return client.ListActions(ctx, params)
	case actionNLALog:
		return client.GetExecutionLog(ctx, firstNonEmpty(stringParam(params, "execution_log_id"), stringParam(params, "id")))
	case actionNLAExecute, actionNLAPreview:
		return client.ExecuteAction(ctx, zapierapi.ExecuteRequest{
			ActionID:     stringParam(params, "action_id"),
			Instructions: stringParam(params, "instruction"),
			PreviewOnly:  action == actionNLAPreview || boolParam(params, "preview_only", false),
			ParamsHints:  objectParam(params, "params_hints"),
		})
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
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
	case actionNLAExecute, actionNLAPreview:
		if stringParam(params, "instruction") == "" {
			return fmt.Errorf("instruction is required")
		}
	case actionNLALog:
		if firstNonEmpty(stringParam(params, "execution_log_id"), stringParam(params, "id")) == "" {
			return fmt.Errorf("execution_log_id is required")
		}
	case actionWebhookSend:
		if stringParam(params, "webhook_name") == "" {
			return fmt.Errorf("webhook_name is required")
		}
	}
	return nil
}

func requiresPinnedActionID(action string, cfg config.Config) bool {
	if action != actionNLAExecute && action != actionNLAPreview {
		return false
	}
	return len(cfg.AllowedActions) > 0 || len(cfg.DeniedActions) > 0
}

func filterActionList(cfg config.Config, result map[string]any) map[string]any {
	if result == nil || (len(cfg.AllowedActions) == 0 && len(cfg.DeniedActions) == 0) {
		return result
	}
	items, ok := result["results"].([]any)
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
		candidate := firstNonEmpty(stringValue(mapped["id"]), stringValue(mapped["action_id"]), stringValue(mapped["key"]))
		if candidate == "" || cfg.IsActionAllowed(candidate) {
			filtered = append(filtered, item)
		}
	}
	result["results"] = filtered
	return result
}

func additionalResultsFromResult(result map[string]any) []any {
	if result == nil {
		return nil
	}
	if values, ok := result["additional_results"].([]any); ok {
		return values
	}
	if values, ok := result["additionalResults"].([]any); ok {
		return values
	}
	return nil
}

func actionUsedFromResult(result map[string]any) string {
	if result == nil {
		return ""
	}
	return firstNonEmpty(stringValue(result["action_used"]), stringValue(result["actionUsed"]), stringValue(result["action"]))
}

func executionLogIDFromResult(result map[string]any) string {
	if result == nil {
		return ""
	}
	return firstNonEmpty(stringValue(result["execution_log_id"]), stringValue(result["executionLogId"]), stringValue(result["executionLogID"]))
}

func statusCodeFromResult(result map[string]any, fallback int) int {
	if result == nil {
		return fallback
	}
	if value := intValue(result["status_code"]); value > 0 {
		return value
	}
	return fallback
}

func statusFromResult(result map[string]any) string {
	if result == nil {
		return ""
	}
	if value := firstNonEmpty(stringValue(result["status"]), stringValue(result["state"])); value != "" {
		return value
	}
	return statusFromHTTP(statusCodeFromResult(result, 0))
}

func statusFromHTTP(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "success"
	case statusCode >= 400 && statusCode < 500:
		return "client_error"
	case statusCode >= 500:
		return "server_error"
	default:
		return ""
	}
}

func objectParam(params map[string]any, key string) map[string]any {
	if params == nil {
		return map[string]any{}
	}
	if mapped, ok := params[key].(map[string]any); ok {
		return mapped
	}
	return map[string]any{}
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
