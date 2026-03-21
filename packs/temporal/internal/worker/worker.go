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

	"github.com/cordum-io/cordum-packs/packs/temporal/internal/config"
	"github.com/cordum-io/cordum-packs/packs/temporal/internal/temporalclient"
)

const (
	topicRead        = "job.temporal.read"
	topicWrite       = "job.temporal.write"
	topicDestructive = "job.temporal.destructive"
)

type actionSpec struct {
	Intent string // "read", "write", "destructive"
}

var actionSpecs = map[string]actionSpec{
	"workflow.start":     {Intent: "write"},
	"workflow.signal":    {Intent: "write"},
	"workflow.query":     {Intent: "read"},
	"workflow.describe":  {Intent: "read"},
	"workflow.cancel":    {Intent: "destructive"},
	"workflow.terminate": {Intent: "destructive"},
	"workflow.list":      {Intent: "read"},
	"schedule.create":   {Intent: "write"},
	"schedule.list":     {Intent: "read"},
	"schedule.describe": {Intent: "read"},
	"schedule.delete":   {Intent: "destructive"},
	"schedule.pause":    {Intent: "write"},
	"schedule.unpause":  {Intent: "write"},
}

type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
	client   *temporalclient.Client
}

type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
}

type JobResult struct {
	JobID         string `json:"job_id"`
	Profile       string `json:"profile"`
	Action        string `json:"action"`
	StatusCode    int    `json:"status_code"`
	DurationMs    int64  `json:"duration_ms"`
	WorkflowID    string `json:"workflow_id,omitempty"`
	RunID         string `json:"run_id,omitempty"`
	ScheduleID    string `json:"schedule_id,omitempty"`
	ExecutionInfo any    `json:"execution_info,omitempty"`
	QueryResult   any    `json:"query_result,omitempty"`
	Result        any    `json:"result,omitempty"`
	Error         string `json:"error,omitempty"`
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "temporal")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("redis store: %w", err)
	}

	w := &Worker{
		cfg:      cfg,
		agent:    &runtime.Agent{NATS: nc, Store: store, RedisURL: cfg.RedisURL, SenderID: workerID},
		natsConn: nc,
		workerID: workerID,
		client:   temporalclient.NewClient(cfg),
	}
	if cfg.MaxParallel > 0 {
		w.sem = make(chan struct{}, cfg.MaxParallel)
	}
	return w, nil
}

func (w *Worker) Close() error {
	if w.agent != nil {
		_ = w.agent.Close()
	}
	return nil
}

func (w *Worker) Run(ctx context.Context) error {
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}
	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{topicRead, topicWrite, topicDestructive}
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
	slog.Info("temporal worker started", "worker_id", w.workerID, "host", w.cfg.TemporalHost, "namespace", w.cfg.Namespace)
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

	action := strings.TrimSpace(input.Action)
	if action == "" {
		return JobResult{JobID: jobID, Error: "action is required"}, nil
	}

	spec, ok := actionSpecs[action]
	if !ok {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("unsupported action: %s", action)}, nil
	}

	// Topic-intent enforcement
	topicIntent := "read"
	if topic == topicWrite {
		topicIntent = "write"
	} else if topic == topicDestructive {
		topicIntent = "destructive"
	}
	if spec.Intent == "destructive" && topicIntent != "destructive" {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("action %q requires destructive topic", action)}, nil
	}
	if spec.Intent == "write" && topicIntent == "read" {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("action %q requires write topic", action)}, nil
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	// Validate task queue and workflow type
	if taskQueue, ok := params["task_queue"].(string); ok && taskQueue != "" {
		if !w.cfg.IsTaskQueueAllowed(taskQueue) {
			return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("task queue %q is not allowed", taskQueue)}, nil
		}
	}
	if wfType, ok := params["workflow_type"].(string); ok && wfType != "" {
		if !w.cfg.IsWorkflowAllowed(wfType) {
			return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("workflow type %q is not allowed", wfType)}, nil
		}
	}

	var result JobResult
	result.JobID = jobID
	result.Action = action

	resp, err := dispatchAction(ctx, w.client, action, params)
	result.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
	} else {
		result.Result = resp
		result.StatusCode = 200
	}

	slog.Info("temporal job completed", "job_id", jobID, "action", action, "duration_ms", result.DurationMs, "error", result.Error)
	return result, nil
}

func dispatchAction(ctx context.Context, client *temporalclient.Client, action string, params map[string]any) (any, error) {
	switch action {
	case "workflow.start":
		return client.StartWorkflow(ctx, params)
	case "workflow.signal":
		return client.SignalWorkflow(ctx, params)
	case "workflow.query":
		return client.QueryWorkflow(ctx, params)
	case "workflow.describe":
		return client.DescribeWorkflow(ctx, params)
	case "workflow.cancel":
		return client.CancelWorkflow(ctx, params)
	case "workflow.terminate":
		return client.TerminateWorkflow(ctx, params)
	case "workflow.list":
		return client.ListWorkflows(ctx, params)
	default:
		return nil, fmt.Errorf("unhandled action: %s", action)
	}
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
