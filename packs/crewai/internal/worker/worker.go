package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/crewai/internal/callback"
	"github.com/cordum-io/cordum-packs/packs/crewai/internal/config"
	"github.com/cordum-io/cordum-packs/packs/crewai/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/crewai/internal/sidecar"
)

const (
	actionCrewRun    = "crew.run"
	actionTaskRun    = "task.execute"
	defaultPackID    = "crewai"
	defaultToolLabel = "tool-execution"
)

type Worker struct {
	cfg            config.Config
	agent          *runtime.Agent
	natsConn       *nats.Conn
	workerID       string
	sem            chan struct{}
	active         int32
	logger         *slog.Logger
	sidecarClient  *http.Client
	callbackServer *callback.CallbackServer
	sidecarManager *sidecar.SidecarManager
	executeFunc    func(context.Context, sidecarExecuteRequest) (sidecarExecuteResponse, error)
}

type JobInput struct {
	CrewConfig     map[string]any `json:"crew_config"`
	TaskConfig     map[string]any `json:"task_config"`
	Input          any            `json:"input"`
	Context        []any          `json:"context"`
	ToolGovernance *bool          `json:"tool_governance"`
	TraceID        string         `json:"trace_id"`
}

type callResult struct {
	JobID       string           `json:"job_id"`
	Action      string           `json:"action"`
	StatusCode  int              `json:"status_code"`
	DurationMs  int64            `json:"duration_ms"`
	CrewOutput  any              `json:"crew_output,omitempty"`
	TaskOutputs []any            `json:"task_outputs,omitempty"`
	ToolCalls   []map[string]any `json:"tool_calls,omitempty"`
	TokensUsed  map[string]int   `json:"tokens_used,omitempty"`
	Result      any              `json:"result,omitempty"`
	Error       string           `json:"error,omitempty"`
}

type sidecarExecuteRequest struct {
	Action      string         `json:"action"`
	Config      map[string]any `json:"config"`
	Input       any            `json:"input"`
	CallbackURL string         `json:"callback_url"`
}

type sidecarExecuteResponse struct {
	OK     bool           `json:"ok"`
	Result map[string]any `json:"result"`
	Error  *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", defaultPackID)
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		nc.Close()
		return nil, err
	}

	agent := &runtime.Agent{
		NATS:     nc,
		Store:    store,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	w := &Worker{
		cfg:      cfg,
		agent:    agent,
		natsConn: nc,
		workerID: workerID,
		logger:   slog.Default(),
		sidecarClient: &http.Client{
			Timeout: cfg.RequestTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	if cfg.MaxParallel > 0 {
		w.sem = make(chan struct{}, cfg.MaxParallel)
	}
	w.executeFunc = w.executeSidecar
	return w, nil
}

func (w *Worker) Close() error {
	if w.sidecarManager != nil {
		_ = w.sidecarManager.Stop()
	}
	if w.callbackServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.callbackServer.Shutdown(ctx)
	}
	if w.agent != nil {
		_ = w.agent.Close()
	}
	return nil
}

func (w *Worker) Run(ctx context.Context) error {
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}
	if err := w.startSidecarRuntime(ctx); err != nil {
		return err
	}
	defer w.Close()

	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{"job.crewai.*"}
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

	<-ctx.Done()
	return ctx.Err()
}

func (w *Worker) startSidecarRuntime(ctx context.Context) error {
	if w.callbackServer != nil && w.sidecarManager != nil {
		return nil
	}

	gateway := gatewayclient.New(w.cfg.GatewayURL, w.cfg.APIKey, w.cfg.TenantID)
	callbackServer, err := callback.NewCallbackServer(callback.CallbackConfig{
		Port:             w.cfg.CallbackPort,
		GatewayClient:    gateway,
		NATSConn:         w.natsConn,
		ToolTopic:        w.cfg.ToolTopic,
		PackID:           defaultPackID,
		CapabilityPrefix: defaultPackID + ".tool",
		DefaultRiskTags:  []string{"write", defaultToolLabel},
		DefaultRequires:  []string{"network:egress"},
		Logger:           w.logger,
		WaitTimeout:      w.cfg.CallbackWaitTimeout,
		SenderID:         w.workerID,
	})
	if err != nil {
		return err
	}
	if err := callbackServer.Start(); err != nil {
		return err
	}

	manager, err := sidecar.NewSidecarManager(sidecar.ManagerConfig{
		Command:     w.cfg.SidecarCommand,
		Args:        w.cfg.SidecarArgs,
		CallbackURL: callbackServer.URL(),
		Logger:      w.logger,
		Env: map[string]string{
			"PYTHONPATH":               w.cfg.SidecarPythonPath,
			"PYTHONUNBUFFERED":         "1",
			"CORDUM_CREWAI_MAX_RPM":    strconv.Itoa(w.cfg.MaxRPM),
			"CORDUM_SIDECAR_LOG_LEVEL": "INFO",
		},
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		return err
	}
	if err := manager.Start(ctx); err != nil {
		_ = callbackServer.Shutdown(context.Background())
		return err
	}

	w.callbackServer = callbackServer
	w.sidecarManager = manager
	return nil
}

func (w *Worker) handleJob(ctx runtime.Context, payload map[string]any) (callResult, error) {
	if w.sem != nil {
		w.sem <- struct{}{}
		atomic.AddInt32(&w.active, 1)
		defer func() {
			<-w.sem
			atomic.AddInt32(&w.active, -1)
		}()
	} else {
		atomic.AddInt32(&w.active, 1)
		defer atomic.AddInt32(&w.active, -1)
	}

	jobID := ""
	jobTopic := ""
	traceID := ""
	if ctx.Job != nil {
		jobID = ctx.Job.GetJobId()
		jobTopic = ctx.Job.GetTopic()
	}
	if strings.TrimSpace(jobTopic) == "" {
		return callResult{}, fmt.Errorf("job topic is required")
	}
	if ctx.Packet != nil {
		traceID = ctx.Packet.GetTraceId()
	}
	tenantID, principalID, actorID, actorType := resolveJobIdentity(ctx, w.cfg.TenantID)

	inputPayload := normalizePayload(payload)
	var input JobInput
	if err := decodePayload(inputPayload, &input); err != nil {
		return callResult{}, err
	}

	if input.ToolGovernance != nil && !*input.ToolGovernance {
		return callResult{}, fmt.Errorf("tool_governance must remain enabled for CrewAI tasks")
	}
	if err := validateInput(jobTopic, input); err != nil {
		return callResult{}, err
	}

	action, err := actionForTopic(jobTopic)
	if err != nil {
		return callResult{}, err
	}
	callbackURL := ""
	if w.callbackServer != nil {
		callbackURL = w.callbackServer.URL()
	}

	execReq := sidecarExecuteRequest{
		Action: action,
		Config: map[string]any{
			"job_id":          jobID,
			"trace_id":        firstNonEmpty(strings.TrimSpace(input.TraceID), traceID),
			"topic":           jobTopic,
			"pack_id":         defaultPackID,
			"tool_topic":      w.cfg.ToolTopic,
			"tenant_id":       tenantID,
			"principal_id":    principalID,
			"actor_id":        actorID,
			"actor_type":      actorType,
			"timeout_seconds": int(w.cfg.RequestTimeout.Seconds()),
			"max_rpm":         w.cfg.MaxRPM,
			"tool_governance": true,
			"context":         input.Context,
		},
		Input:       buildSidecarInput(action, input),
		CallbackURL: callbackURL,
	}

	w.publishProgress(jobID, traceID, 5, "starting "+action)
	start := time.Now()
	callCtx, cancel := context.WithTimeout(context.Background(), w.cfg.RequestTimeout)
	defer cancel()
	response, err := w.executeFunc(callCtx, execReq)
	result := callResult{
		JobID:      jobID,
		Action:     action,
		DurationMs: time.Since(start).Milliseconds(),
	}
	if response.Result != nil {
		result.CrewOutput = response.Result["crew_output"]
		result.TaskOutputs = extractAnySlice(response.Result["task_outputs"])
		result.ToolCalls = extractMapSlice(response.Result["tool_calls"])
		result.TokensUsed = extractIntMap(response.Result["tokens_used"])
		result.Result = response.Result
	}
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.StatusCode = http.StatusOK
	w.publishProgress(jobID, traceID, 100, "completed "+action)
	return result, nil
}

func (w *Worker) executeSidecar(ctx context.Context, req sidecarExecuteRequest) (sidecarExecuteResponse, error) {
	if w.sidecarManager == nil || w.sidecarManager.Port() == 0 {
		return sidecarExecuteResponse{}, fmt.Errorf("sidecar not started")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return sidecarExecuteResponse{}, err
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/execute", w.sidecarManager.Port())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return sidecarExecuteResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if traceID, _ := req.Config["trace_id"].(string); strings.TrimSpace(traceID) != "" {
		httpReq.Header.Set("X-Trace-ID", traceID)
	}

	resp, err := w.sidecarClient.Do(httpReq) // #nosec G107 -- sidecar URL is localhost and manager-controlled.
	if err != nil {
		return sidecarExecuteResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return sidecarExecuteResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return sidecarExecuteResponse{}, fmt.Errorf("sidecar execute failed: %s", strings.TrimSpace(string(body)))
	}
	var decoded sidecarExecuteResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return sidecarExecuteResponse{}, err
	}
	if !decoded.OK {
		if decoded.Error != nil && strings.TrimSpace(decoded.Error.Message) != "" {
			return decoded, errors.New(decoded.Error.Message)
		}
		return decoded, fmt.Errorf("sidecar execute failed")
	}
	return decoded, nil
}

func actionForTopic(topic string) (string, error) {
	switch strings.TrimSpace(topic) {
	case "job.crewai.crew":
		return actionCrewRun, nil
	case "job.crewai.task":
		return actionTaskRun, nil
	default:
		return "", fmt.Errorf("unsupported topic: %s", topic)
	}
}

func buildSidecarInput(action string, input JobInput) map[string]any {
	result := map[string]any{
		"input": input.Input,
	}
	switch action {
	case actionCrewRun:
		result["crew_config"] = input.CrewConfig
	case actionTaskRun:
		result["task_config"] = input.TaskConfig
		result["context"] = input.Context
	}
	return result
}

func validateInput(topic string, input JobInput) error {
	switch strings.TrimSpace(topic) {
	case "job.crewai.crew":
		if len(input.CrewConfig) == 0 {
			return fmt.Errorf("crew_config is required")
		}
		if len(extractAnySlice(input.CrewConfig["agents"])) == 0 {
			return fmt.Errorf("crew_config.agents is required")
		}
		if len(extractAnySlice(input.CrewConfig["tasks"])) == 0 {
			return fmt.Errorf("crew_config.tasks is required")
		}
	case "job.crewai.task":
		if len(input.TaskConfig) == 0 {
			return fmt.Errorf("task_config is required")
		}
		if strings.TrimSpace(extractString(input.TaskConfig["description"])) == "" {
			return fmt.Errorf("task_config.description is required")
		}
	default:
		return fmt.Errorf("unsupported topic: %s", topic)
	}
	return nil
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

func (w *Worker) publishProgress(jobID, traceID string, percent int32, message string) {
	if w.natsConn == nil || strings.TrimSpace(jobID) == "" {
		return
	}
	progress := &agentv1.JobProgress{
		JobId:   jobID,
		Percent: percent,
		Message: strings.TrimSpace(message),
		Status:  agentv1.JobStatus_JOB_STATUS_RUNNING,
	}
	_ = runtime.PublishProgress(w.natsConn, progress, traceID, w.workerID, nil)
}

func extractAnySlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case nil:
		return nil
	default:
		return []any{typed}
	}
}

func extractMapSlice(value any) []map[string]any {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if mapped, ok := item.(map[string]any); ok {
			out = append(out, mapped)
		}
	}
	return out
}

func extractIntMap(value any) map[string]int {
	mapped, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]int, len(mapped))
	for key, raw := range mapped {
		switch typed := raw.(type) {
		case int:
			out[key] = typed
		case int64:
			out[key] = int(typed)
		case float64:
			out[key] = int(typed)
		}
	}
	return out
}

func extractString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func resolveJobIdentity(ctx runtime.Context, fallbackTenant string) (tenantID, principalID, actorID, actorType string) {
	tenantID = strings.TrimSpace(fallbackTenant)
	if ctx.Job == nil {
		return tenantID, "", "", ""
	}

	if candidate := strings.TrimSpace(ctx.Job.GetTenantId()); candidate != "" {
		tenantID = candidate
	}
	principalID = strings.TrimSpace(ctx.Job.GetPrincipalId())

	if meta := ctx.Job.GetMeta(); meta != nil {
		if candidate := strings.TrimSpace(meta.GetTenantId()); candidate != "" {
			tenantID = candidate
		}
		actorID = strings.TrimSpace(meta.GetActorId())
		if raw := strings.TrimSpace(meta.GetActorType().String()); raw != "" && raw != "ACTOR_TYPE_UNSPECIFIED" {
			actorType = strings.ToLower(strings.TrimPrefix(raw, "ACTOR_TYPE_"))
		}
	}

	return tenantID, principalID, actorID, actorType
}
