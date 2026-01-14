package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/hello-pack/internal/config"
	"github.com/cordum-io/cordum-packs/packs/hello-pack/internal/gatewayclient"
)

const topicEcho = "job.hello-pack.echo"

type Worker struct {
	cfg     config.Config
	gateway *gatewayclient.Client
	redis   *redis.Client
	worker  *runtime.Worker
}

type HelloInput struct {
	Message string `json:"message"`
	Author  string `json:"author"`
}

type HelloOutput struct {
	Echo       string         `json:"echo"`
	JobID      string         `json:"job_id"`
	ReceivedAt string         `json:"received_at"`
	Input      map[string]any `json:"input,omitempty"`
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.GatewayURL == "" {
		return nil, fmt.Errorf("gateway url required")
	}
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	redisClient := redis.NewClient(opts)

	worker, err := runtime.NewWorker(runtime.Config{
		Pool:            cfg.Pool,
		Subjects:        cfg.Subjects,
		Queue:           cfg.Queue,
		NatsURL:         cfg.NatsURL,
		MaxParallelJobs: cfg.MaxParallel,
		Capabilities:    []string{"hello-pack"},
		Labels:          map[string]string{"adapter": "hello-pack"},
		Type:            "hello-pack",
	})
	if err != nil {
		return nil, err
	}

	return &Worker{
		cfg:     cfg,
		gateway: gatewayclient.New(cfg.GatewayURL, cfg.APIKey),
		redis:   redisClient,
		worker:  worker,
	}, nil
}

func (w *Worker) Close() error {
	if w.worker != nil {
		_ = w.worker.Close()
	}
	if w.redis != nil {
		_ = w.redis.Close()
	}
	return nil
}

func (w *Worker) Run(ctx context.Context) error {
	return w.worker.Run(ctx, w.handleJob)
}

func (w *Worker) handleJob(ctx context.Context, req *agentv1.JobRequest) (*agentv1.JobResult, error) {
	jobID := req.GetJobId()
	ctxPtr := req.GetContextPtr()
	if ctxPtr == "" && req.Env != nil {
		ctxPtr = req.Env["context_ptr"]
	}
	payload, err := w.fetchPayload(ctx, ctxPtr)
	if err != nil {
		return w.failJob(jobID, err)
	}

	if req.GetTopic() != topicEcho {
		return w.failJob(jobID, fmt.Errorf("unsupported topic: %s", req.GetTopic()))
	}

	var input HelloInput
	if err := decodePayload(payload, &input); err != nil {
		return w.failJob(jobID, err)
	}
	if strings.TrimSpace(input.Message) == "" {
		return w.failJob(jobID, fmt.Errorf("message required"))
	}

	result := HelloOutput{
		Echo:       fmt.Sprintf("%s", strings.TrimSpace(input.Message)),
		JobID:      jobID,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Input:      payload,
	}

	return w.finishJob(jobID, result, nil)
}

func (w *Worker) fetchPayload(ctx context.Context, ptr string) (map[string]any, error) {
	if strings.TrimSpace(ptr) == "" {
		return nil, fmt.Errorf("context_ptr missing")
	}
	mem, err := w.gateway.GetMemory(ctx, ptr)
	if err != nil {
		return nil, err
	}
	payload, ok := mem.JSON.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected context format")
	}
	if ctxPayload, ok := payload["context"].(map[string]any); ok {
		payload = ctxPayload
	}
	return payload, nil
}

func decodePayload(payload map[string]any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (w *Worker) finishJob(jobID string, result any, err error) (*agentv1.JobResult, error) {
	ptr, storeErr := w.storeResult(context.Background(), jobID, result)
	if storeErr != nil {
		return &agentv1.JobResult{JobId: jobID, Status: agentv1.JobStatus_JOB_STATUS_FAILED, ErrorMessage: storeErr.Error()}, storeErr
	}
	status := agentv1.JobStatus_JOB_STATUS_SUCCEEDED
	if err != nil {
		status = agentv1.JobStatus_JOB_STATUS_FAILED
	}
	return &agentv1.JobResult{JobId: jobID, Status: status, ResultPtr: ptr}, err
}

func (w *Worker) failJob(jobID string, err error) (*agentv1.JobResult, error) {
	return &agentv1.JobResult{JobId: jobID, Status: agentv1.JobStatus_JOB_STATUS_FAILED, ErrorMessage: err.Error()}, err
}

func (w *Worker) storeResult(ctx context.Context, jobID string, payload any) (string, error) {
	if w.redis == nil {
		return "", fmt.Errorf("redis client unavailable")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	key := "res:" + jobID
	if err := w.redis.Set(ctx, key, data, w.cfg.ResultTTL).Err(); err != nil {
		return "", err
	}
	return "redis://" + key, nil
}
