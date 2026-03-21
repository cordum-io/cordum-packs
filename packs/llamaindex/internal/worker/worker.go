package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	sidecar "github.com/cordum-io/cordum-packs/integrations/sidecar-template/go"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/llamaindex/internal/config"
)

const (
	topicQuery    = "job.llamaindex.query"
	topicRetrieve = "job.llamaindex.retrieve"
	topicIndex    = "job.llamaindex.index"
	topicIngest   = "job.llamaindex.ingest"
)

// Worker handles LlamaIndex pack jobs via Python sidecar.
type Worker struct {
	cfg            config.Config
	agent          *runtime.Agent
	natsConn       *nats.Conn
	workerID       string
	sem            chan struct{}
	active         int32
	sidecarManager *sidecar.SidecarManager
	sidecarClient  *http.Client
}

// JobInput is the incoming job payload.
type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Config    map[string]any `json:"config"`
	Input     any            `json:"input"`
	RequestID string         `json:"request_id"`
}

// JobResult is the output payload.
type JobResult struct {
	JobID              string `json:"job_id"`
	Profile            string `json:"profile"`
	Action             string `json:"action"`
	DurationMs         int64  `json:"duration_ms"`
	Response           string `json:"response,omitempty"`
	SourceNodes        any    `json:"source_nodes,omitempty"`
	IndexID            string `json:"index_id,omitempty"`
	DocumentsIngested  int    `json:"documents_ingested,omitempty"`
	Result             any    `json:"result,omitempty"`
	Error              string `json:"error,omitempty"`
}

// New creates a new LlamaIndex worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "llamaindex")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("redis store: %w", err)
	}

	sidecarMgr, err := sidecar.NewSidecarManager(sidecar.ManagerConfig{
		Command: cfg.PythonCommand,
		Args:    []string{"-m", cfg.SidecarModule},
		Port:    cfg.SidecarPort,
		Env:     cfg.SidecarEnv,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("sidecar manager: %w", err)
	}

	w := &Worker{
		cfg:            cfg,
		agent:          &runtime.Agent{NATS: nc, Store: store, RedisURL: cfg.RedisURL, SenderID: workerID},
		natsConn:       nc,
		workerID:       workerID,
		sidecarManager: sidecarMgr,
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

func (w *Worker) Close() error {
	if w.sidecarManager != nil {
		_ = w.sidecarManager.Stop()
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

	if err := w.sidecarManager.Start(ctx); err != nil {
		return fmt.Errorf("sidecar start: %w", err)
	}
	slog.Info("python sidecar started", "port", w.sidecarManager.Port())

	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{topicQuery, topicRetrieve, topicIndex, topicIngest}
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

	slog.Info("llamaindex worker started", "worker_id", w.workerID, "subjects", subjects, "sidecar_port", w.sidecarManager.Port())
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
		case topicQuery:
			action = "query"
		case topicRetrieve:
			action = "retrieve"
		case topicIndex:
			action = "index"
		case topicIngest:
			action = "ingest"
		default:
			action = "query"
		}
	}
	result.Action = action

	if !w.sidecarManager.IsHealthy() {
		result.Error = "python sidecar is not healthy"
		result.DurationMs = time.Since(start).Milliseconds()
		return result, nil
	}

	sidecarReq := map[string]any{
		"action":       action,
		"config":       input.Config,
		"input":        input.Input,
		"callback_url": "",
	}

	sidecarResp, err := w.callSidecar(ctx, jobID, sidecarReq)
	if err != nil {
		result.Error = err.Error()
		result.DurationMs = time.Since(start).Milliseconds()
		return result, nil
	}

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

	if sidecarResult, ok := sidecarResp["result"].(map[string]any); ok {
		if resp, ok := sidecarResult["response"].(string); ok {
			result.Response = resp
		}
		result.SourceNodes = sidecarResult["source_nodes"]
		if id, ok := sidecarResult["index_id"].(string); ok {
			result.IndexID = id
		}
		if count, ok := sidecarResult["documents_ingested"].(float64); ok {
			result.DocumentsIngested = int(count)
		}
		result.Result = sidecarResult
	} else {
		result.Result = sidecarResp["result"]
	}

	result.DurationMs = time.Since(start).Milliseconds()
	slog.Info("llamaindex job completed", "job_id", jobID, "action", action, "duration_ms", result.DurationMs, "error", result.Error)
	return result, nil
}

func (w *Worker) callSidecar(ctx context.Context, jobID string, request map[string]any) (map[string]any, error) {
	sidecarURL := fmt.Sprintf("http://127.0.0.1:%d/execute", w.sidecarManager.Port())
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, sidecarURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Job-ID", jobID)

	resp, err := w.sidecarClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
