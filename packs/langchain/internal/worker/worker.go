package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	sdkclient "github.com/cordum/cordum/sdk/client"
	sidecar "github.com/cordum-io/cordum-packs/integrations/sidecar-template/go"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/langchain/internal/config"
)

const (
	topicChain     = "job.langchain.chain"
	topicAgent     = "job.langchain.agent"
	topicRetriever = "job.langchain.retriever"
	topicToolcall  = "job.langchain.toolcall"
)

// Worker handles LangChain pack jobs via a Python sidecar.
type Worker struct {
	cfg            config.Config
	agent          *runtime.Agent
	natsConn       *nats.Conn
	workerID       string
	sem            chan struct{}
	active         int32
	sidecarManager *sidecar.SidecarManager
	callbackServer *sidecar.CallbackServer
	sidecarClient  *http.Client
}

// JobInput is the incoming job payload.
type JobInput struct {
	Profile        string         `json:"profile"`
	Action         string         `json:"action"`
	Config         map[string]any `json:"config"`
	Input          any            `json:"input"`
	Query          string         `json:"query"`
	K              int            `json:"k"`
	ToolGovernance *bool          `json:"tool_governance,omitempty"`
	RequestID      string         `json:"request_id"`
}

// JobResult is the output payload for all LangChain jobs.
type JobResult struct {
	JobID             string `json:"job_id"`
	Profile           string `json:"profile"`
	Action            string `json:"action"`
	DurationMs        int64  `json:"duration_ms"`
	Output            any    `json:"output,omitempty"`
	IntermediateSteps any    `json:"intermediate_steps,omitempty"`
	ToolCalls         any    `json:"tool_calls,omitempty"`
	TokensUsed        any    `json:"tokens_used,omitempty"`
	Documents         any    `json:"documents,omitempty"`
	Error             string `json:"error,omitempty"`
}

// New creates a new LangChain worker with sidecar and callback server.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "langchain")
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

	// Create gateway client for governance callback
	gwClient := sdkclient.New(cfg.GatewayURL, cfg.APIKey)
	gwClient.TenantID = cfg.TenantID

	// Create callback server (governance bridge: Python sidecar → Go → NATS → Safety Kernel)
	callbackServer, err := sidecar.NewCallbackServer(sidecar.CallbackConfig{
		Port:             0, // auto-allocate
		GatewayClient:    gwClient,
		NATSConn:         nc,
		ToolTopic:        cfg.ToolCallTopic,
		PackID:           "langchain",
		CapabilityPrefix: cfg.CapabilityPrefix,
		DefaultRiskTags:  []string{"tool", "governance", "write"},
		DefaultRequires:  []string{"network:egress"},
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("callback server: %w", err)
	}

	// Create sidecar manager (Python subprocess lifecycle)
	sidecarMgr, err := sidecar.NewSidecarManager(sidecar.ManagerConfig{
		Command:     cfg.PythonCommand,
		Args:        []string{"-m", cfg.SidecarModule},
		Port:        cfg.SidecarPort,
		CallbackURL: "", // Set after callback server starts
		Env:         cfg.SidecarEnv,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("sidecar manager: %w", err)
	}

	w := &Worker{
		cfg:            cfg,
		agent:          runtimeAgent,
		natsConn:       nc,
		workerID:       workerID,
		sidecarManager: sidecarMgr,
		callbackServer: callbackServer,
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
	return w, nil
}

// Close shuts down the worker, sidecar, and callback server.
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

// Run starts the callback server, sidecar, and worker loop.
func (w *Worker) Run(ctx context.Context) error {
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}

	// 1. Start callback server first (sidecar needs its URL)
	if err := w.callbackServer.Start(); err != nil {
		return fmt.Errorf("callback server start: %w", err)
	}
	slog.Info("callback server started", "url", w.callbackServer.URL())

	// 2. Start sidecar with callback URL
	// Re-create sidecar manager with the now-known callback URL
	sidecarMgr, err := sidecar.NewSidecarManager(sidecar.ManagerConfig{
		Command:     w.cfg.PythonCommand,
		Args:        []string{"-m", w.cfg.SidecarModule},
		Port:        w.cfg.SidecarPort,
		CallbackURL: w.callbackServer.URL(),
		Env:         w.cfg.SidecarEnv,
	})
	if err != nil {
		return fmt.Errorf("sidecar manager recreate: %w", err)
	}
	w.sidecarManager = sidecarMgr

	if err := w.sidecarManager.Start(ctx); err != nil {
		return fmt.Errorf("sidecar start: %w", err)
	}
	slog.Info("python sidecar started", "port", w.sidecarManager.Port())

	// 3. Register topics and start runtime agent
	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{topicChain, topicAgent, topicRetriever, topicToolcall}
	}
	for _, subject := range subjects {
		runtime.Register(w.agent, subject, w.handleJob)
	}
	runtime.Register(w.agent, runtime.DirectSubject(w.workerID), w.handleJob)

	if err := w.agent.Start(); err != nil {
		return fmt.Errorf("agent start: %w", err)
	}

	// 4. Heartbeat
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

	slog.Info("langchain worker started",
		"worker_id", w.workerID,
		"subjects", subjects,
		"tool_governance", w.cfg.ToolGovernance,
		"sidecar_port", w.sidecarManager.Port(),
		"callback_url", w.callbackServer.URL(),
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

	// Determine action from topic
	action := input.Action
	if action == "" {
		switch topic {
		case topicChain:
			action = "chain.invoke"
		case topicAgent:
			action = "agent.invoke"
		case topicRetriever:
			action = "retriever.invoke"
		default:
			action = "chain.invoke"
		}
	}
	result.Action = action

	// Check sidecar health
	if !w.sidecarManager.IsHealthy() {
		result.Error = "python sidecar is not healthy"
		result.DurationMs = time.Since(start).Milliseconds()
		return result, nil
	}

	// Determine callback URL for this request
	callbackURL := ""
	governance := w.cfg.ToolGovernance
	if input.ToolGovernance != nil {
		governance = *input.ToolGovernance
	}
	if governance {
		callbackURL = w.callbackServer.URL()
	}

	// Build sidecar request
	sidecarReq := map[string]any{
		"action":       action,
		"config":       input.Config,
		"input":        input.Input,
		"callback_url": callbackURL,
	}
	if input.Query != "" {
		sidecarReq["input"] = map[string]any{"query": input.Query, "k": input.K}
	}

	// Execute via sidecar
	sidecarResp, err := w.callSidecar(ctx, jobID, sidecarReq)
	if err != nil {
		result.Error = err.Error()
		result.DurationMs = time.Since(start).Milliseconds()
		return result, nil
	}

	// Parse sidecar response
	if ok, _ := sidecarResp["ok"].(bool); !ok {
		if errObj, exists := sidecarResp["error"]; exists {
			if errMap, ok := errObj.(map[string]any); ok {
				if msg, ok := errMap["message"].(string); ok {
					result.Error = msg
				}
			} else if errStr, ok := errObj.(string); ok {
				result.Error = errStr
			}
		}
		if result.Error == "" {
			result.Error = "sidecar execution failed"
		}
		result.DurationMs = time.Since(start).Milliseconds()
		return result, nil
	}

	// Extract result fields
	if sidecarResult, ok := sidecarResp["result"].(map[string]any); ok {
		result.Output = sidecarResult["output"]
		result.IntermediateSteps = sidecarResult["intermediate_steps"]
		result.ToolCalls = sidecarResult["tool_calls"]
		result.TokensUsed = sidecarResult["tokens_used"]
		result.Documents = sidecarResult["documents"]
	} else {
		result.Output = sidecarResp["result"]
	}

	result.DurationMs = time.Since(start).Milliseconds()

	slog.Info("langchain job completed",
		"job_id", jobID,
		"topic", topic,
		"action", action,
		"duration_ms", result.DurationMs,
		"error", result.Error,
	)

	return result, nil
}

// callSidecar sends a request to the Python sidecar's /execute endpoint.
func (w *Worker) callSidecar(ctx context.Context, jobID string, request map[string]any) (map[string]any, error) {
	sidecarURL := fmt.Sprintf("http://127.0.0.1:%d/execute", w.sidecarManager.Port())

	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal sidecar request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, sidecarURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create sidecar request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Job-ID", jobID)

	resp, err := w.sidecarClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sidecar request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read sidecar response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("sidecar error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode sidecar response: %w", err)
	}

	return result, nil
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
