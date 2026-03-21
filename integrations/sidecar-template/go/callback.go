package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	sdkclient "github.com/cordum/cordum/sdk/client"
	"github.com/nats-io/nats.go"
)

const (
	defaultToolCallTopic   = "job.framework.toolcall"
	defaultCallbackTimeout = 2 * time.Minute
	defaultPollInterval    = 250 * time.Millisecond
)

// GatewayClient describes the subset of gateway behavior the template requires.
type GatewayClient interface {
	SubmitJob(ctx context.Context, req *sdkclient.JobSubmitRequest) (*sdkclient.JobSubmitResponse, error)
	GetJob(ctx context.Context, jobID string) (map[string]any, error)
}

// JobWaiter allows packs to replace the default gateway polling behavior.
type JobWaiter interface {
	Wait(ctx context.Context, jobID string) (*JobOutcome, error)
}

// CallbackConfig configures the governance callback server.
type CallbackConfig struct {
	Port               int
	GatewayClient      GatewayClient
	NATSConn           *nats.Conn
	ToolTopic          string
	PackID             string
	CapabilityPrefix   string
	Logger             *slog.Logger
	PollInterval       time.Duration
	WaitTimeout        time.Duration
	DefaultRiskTags    []string
	DefaultRequires    []string
	RiskTagResolver    func(ToolCallRequest) []string
	RequiresResolver   func(ToolCallRequest) []string
	CustomResultWaiter JobWaiter
}

// CallbackServer receives governance requests from a Python sidecar.
type CallbackServer struct {
	port             int
	gatewayClient    GatewayClient
	natsConn         *nats.Conn
	toolTopic        string
	packID           string
	capabilityPrefix string
	logger           *slog.Logger
	pollInterval     time.Duration
	waitTimeout      time.Duration
	defaultRiskTags  []string
	defaultRequires  []string
	riskTagResolver  func(ToolCallRequest) []string
	requiresResolver func(ToolCallRequest) []string
	waiter           JobWaiter

	server   *http.Server
	listener net.Listener
}

// ToolCallRequest is sent by the Python sidecar before executing a governed tool.
type ToolCallRequest struct {
	ToolName       string            `json:"tool_name"`
	Arguments      map[string]any    `json:"arguments"`
	TraceID        string            `json:"trace_id,omitempty"`
	Prompt         string            `json:"prompt,omitempty"`
	Topic          string            `json:"topic,omitempty"`
	PackID         string            `json:"pack_id,omitempty"`
	Capability     string            `json:"capability,omitempty"`
	RiskTags       []string          `json:"risk_tags,omitempty"`
	Requires       []string          `json:"requires,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	TenantID       string            `json:"tenant_id,omitempty"`
	PrincipalID    string            `json:"principal_id,omitempty"`
	ActorID        string            `json:"actor_id,omitempty"`
	ActorType      string            `json:"actor_type,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
	TimeoutMs      int               `json:"timeout_ms,omitempty"`
}

// ToolCallResponse is returned to the Python sidecar after policy/governance completes.
type ToolCallResponse struct {
	Approved bool   `json:"approved"`
	Result   any    `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
	JobID    string `json:"job_id,omitempty"`
	TraceID  string `json:"trace_id,omitempty"`
	Status   string `json:"status,omitempty"`
}

// JobOutcome is the normalized terminal job state exposed to callback handlers.
type JobOutcome struct {
	Approved bool
	Result   any
	Error    string
	Status   string
}

// NewCallbackServer returns a ready-to-start callback server.
func NewCallbackServer(cfg CallbackConfig) (*CallbackServer, error) {
	if cfg.GatewayClient == nil {
		return nil, fmt.Errorf("gateway client is required")
	}

	toolTopic := strings.TrimSpace(cfg.ToolTopic)
	if toolTopic == "" {
		toolTopic = defaultToolCallTopic
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	server := &CallbackServer{
		port:             cfg.Port,
		gatewayClient:    cfg.GatewayClient,
		natsConn:         cfg.NATSConn,
		toolTopic:        toolTopic,
		packID:           strings.TrimSpace(cfg.PackID),
		capabilityPrefix: strings.TrimSpace(cfg.CapabilityPrefix),
		logger:           logger,
		pollInterval:     durationOrDefault(cfg.PollInterval, defaultPollInterval),
		waitTimeout:      durationOrDefault(cfg.WaitTimeout, defaultCallbackTimeout),
		defaultRiskTags:  append([]string(nil), cfg.DefaultRiskTags...),
		defaultRequires:  append([]string(nil), cfg.DefaultRequires...),
		riskTagResolver:  cfg.RiskTagResolver,
		requiresResolver: cfg.RequiresResolver,
		waiter:           cfg.CustomResultWaiter,
	}

	if len(server.defaultRiskTags) == 0 {
		server.defaultRiskTags = []string{"tool", "governance"}
	}
	if len(server.defaultRequires) == 0 {
		server.defaultRequires = []string{"network:egress"}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", server.handleHealth)
	mux.HandleFunc("/tool-call", server.handleToolCall)
	mux.HandleFunc("/shutdown", server.handleShutdown)

	server.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return server, nil
}

// Start binds a localhost listener and begins serving requests.
func (s *CallbackServer) Start() error {
	if s.server == nil {
		return fmt.Errorf("callback server not initialized")
	}
	if s.listener != nil {
		return nil
	}

	address := fmt.Sprintf("127.0.0.1:%d", s.port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen callback server: %w", err)
	}
	s.listener = listener

	if addr, ok := listener.Addr().(*net.TCPAddr); ok {
		s.port = addr.Port
	}

	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("callback server stopped unexpectedly", "error", err)
		}
	}()

	return nil
}

// Shutdown gracefully stops the callback server.
func (s *CallbackServer) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	err := s.server.Shutdown(ctx)
	s.listener = nil
	return err
}

// URL returns the base callback URL.
func (s *CallbackServer) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", s.port)
}

// Port returns the bound callback server port.
func (s *CallbackServer) Port() int {
	return s.port
}

func (s *CallbackServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"status": "ok",
		"port":   s.port,
	})
}

func (s *CallbackServer) handleShutdown(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "shutting_down"})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	}()
}

func (s *CallbackServer) handleToolCall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResponse(w, http.StatusMethodNotAllowed, ToolCallResponse{
			Approved: false,
			Error:    "method not allowed",
			Status:   "invalid_request",
		})
		return
	}

	var request ToolCallRequest
	if err := decodeToolCallRequest(r, &request); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, ToolCallResponse{
			Approved: false,
			Error:    err.Error(),
			Status:   "invalid_request",
		})
		return
	}

	timeout := s.waitTimeout
	if request.TimeoutMs > 0 {
		timeout = time.Duration(request.TimeoutMs) * time.Millisecond
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	submitRequest := s.buildSubmitRequest(request)
	submitResponse, err := s.gatewayClient.SubmitJob(ctx, submitRequest)
	if err != nil {
		writeJSONResponse(w, http.StatusBadGateway, ToolCallResponse{
			Approved: false,
			Error:    fmt.Sprintf("submit governed job: %v", err),
			Status:   "submit_failed",
			TraceID:  request.TraceID,
		})
		return
	}

	outcome, err := s.waitForResult(ctx, submitResponse.JobID)
	if err != nil {
		statusCode := http.StatusGatewayTimeout
		status := "timeout"
		if !errorsIsDeadline(err) {
			statusCode = http.StatusBadGateway
			status = "wait_failed"
		}
		writeJSONResponse(w, statusCode, ToolCallResponse{
			Approved: false,
			Error:    err.Error(),
			JobID:    submitResponse.JobID,
			TraceID:  submitResponse.TraceID,
			Status:   status,
		})
		return
	}

	response := ToolCallResponse{
		Approved: outcome.Approved,
		Result:   outcome.Result,
		Error:    outcome.Error,
		JobID:    submitResponse.JobID,
		TraceID:  firstNonEmpty(submitResponse.TraceID, request.TraceID),
		Status:   outcome.Status,
	}
	writeJSONResponse(w, http.StatusOK, response)
}

func (s *CallbackServer) buildSubmitRequest(request ToolCallRequest) *sdkclient.JobSubmitRequest {
	capability := strings.TrimSpace(request.Capability)
	if capability == "" {
		if s.capabilityPrefix != "" {
			capability = s.capabilityPrefix + "." + request.ToolName
		} else {
			capability = request.ToolName
		}
	}

	labels := map[string]string{
		"tool_name": request.ToolName,
	}
	for key, value := range request.Labels {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		labels[key] = value
	}
	if request.TraceID != "" {
		labels["trace_id"] = request.TraceID
	}

	return &sdkclient.JobSubmitRequest{
		Prompt:         firstNonEmpty(strings.TrimSpace(request.Prompt), fmt.Sprintf("Governed tool call: %s", request.ToolName)),
		Topic:          firstNonEmpty(strings.TrimSpace(request.Topic), s.toolTopic),
		Context:        map[string]any{"tool_name": request.ToolName, "arguments": request.Arguments, "trace_id": request.TraceID},
		TenantID:       strings.TrimSpace(request.TenantID),
		PrincipalID:    strings.TrimSpace(request.PrincipalID),
		ActorID:        strings.TrimSpace(request.ActorID),
		ActorType:      strings.TrimSpace(request.ActorType),
		IdempotencyKey: strings.TrimSpace(request.IdempotencyKey),
		PackID:         firstNonEmpty(strings.TrimSpace(request.PackID), s.packID),
		Capability:     capability,
		RiskTags:       s.resolveRiskTags(request),
		Requires:       s.resolveRequires(request),
		Labels:         labels,
	}
}

func (s *CallbackServer) resolveRiskTags(request ToolCallRequest) []string {
	if len(request.RiskTags) > 0 {
		return cleanStringSlice(request.RiskTags)
	}
	if s.riskTagResolver != nil {
		return cleanStringSlice(s.riskTagResolver(request))
	}
	return append([]string(nil), s.defaultRiskTags...)
}

func (s *CallbackServer) resolveRequires(request ToolCallRequest) []string {
	if len(request.Requires) > 0 {
		return cleanStringSlice(request.Requires)
	}
	if s.requiresResolver != nil {
		return cleanStringSlice(s.requiresResolver(request))
	}
	return append([]string(nil), s.defaultRequires...)
}

func (s *CallbackServer) waitForResult(ctx context.Context, jobID string) (*JobOutcome, error) {
	if s.waiter != nil {
		return s.waiter.Wait(ctx, jobID)
	}

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		job, err := s.gatewayClient.GetJob(ctx, jobID)
		if err == nil {
			status := normalizeJobStatus(job["status"])
			if terminalJobStatus(status) {
				return buildOutcome(job, status), nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func buildOutcome(job map[string]any, status string) *JobOutcome {
	result := extractJobResult(job)
	errText := extractJobError(job)

	switch status {
	case "succeeded":
		return &JobOutcome{Approved: true, Result: result, Status: status}
	case "denied":
		if errText == "" {
			errText = "tool call denied by policy"
		}
		return &JobOutcome{Approved: false, Result: result, Error: errText, Status: status}
	default:
		if errText == "" {
			errText = fmt.Sprintf("tool call ended with status %s", status)
		}
		return &JobOutcome{Approved: false, Result: result, Error: errText, Status: status}
	}
}

func decodeToolCallRequest(r *http.Request, out *ToolCallRequest) error {
	if strings.TrimSpace(r.Header.Get("Content-Type")) != "" && !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return fmt.Errorf("content-type must be application/json")
	}

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if strings.TrimSpace(out.ToolName) == "" {
		return fmt.Errorf("tool_name is required")
	}
	if out.Arguments == nil {
		out.Arguments = map[string]any{}
	}
	return nil
}

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
		case "pending", "scheduled", "dispatched", "running":
			return status
		default:
			return status
		}
	case int:
		return mapNumericStatus(float64(typed))
	case int32:
		return mapNumericStatus(float64(typed))
	case int64:
		return mapNumericStatus(float64(typed))
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

func writeJSONResponse(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func cleanStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		candidate := strings.TrimSpace(value)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func errorsIsDeadline(err error) bool {
	return err != nil && (err == context.DeadlineExceeded || strings.Contains(strings.ToLower(err.Error()), "deadline"))
}
