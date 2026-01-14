package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/prometheus-query/internal/config"
	"github.com/cordum-io/cordum-packs/packs/prometheus-query/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/prometheus-query/internal/promapi"
)

const topicRead = "job.prometheus-query.read"

type Worker struct {
	cfg     config.Config
	gateway *gatewayclient.Client
	redis   *redis.Client
	worker  *runtime.Worker
}

type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
}

type callResult struct {
	JobID      string `json:"job_id"`
	Profile    string `json:"profile"`
	Action     string `json:"action"`
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

type actionSpec struct {
	Name         string
	Method       string
	Path         string
	RequiredKeys []string
	ArrayKeys    []string
	PathParam    string
}

var actionSpecs = map[string]actionSpec{
	"query.instant": {Name: "query.instant", Method: "GET", Path: "/api/v1/query", RequiredKeys: []string{"query"}},
	"query.range":   {Name: "query.range", Method: "GET", Path: "/api/v1/query_range", RequiredKeys: []string{"query", "start", "end", "step"}},
	"labels.list":   {Name: "labels.list", Method: "GET", Path: "/api/v1/labels", ArrayKeys: []string{"match"}},
	"label.values":  {Name: "label.values", Method: "GET", Path: "/api/v1/label/{label}/values", PathParam: "label", ArrayKeys: []string{"match"}},
	"series.list":   {Name: "series.list", Method: "GET", Path: "/api/v1/series", RequiredKeys: []string{"match"}, ArrayKeys: []string{"match"}},
	"alerts.list":   {Name: "alerts.list", Method: "GET", Path: "/api/v1/alerts"},
	"rules.list":    {Name: "rules.list", Method: "GET", Path: "/api/v1/rules"},
	"targets.list":  {Name: "targets.list", Method: "GET", Path: "/api/v1/targets"},
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
		Capabilities:    []string{"prometheus"},
		Labels:          map[string]string{"adapter": "prometheus"},
		Type:            "prometheus",
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
	input, err := w.fetchInput(ctx, ctxPtr)
	if err != nil {
		return w.failJob(jobID, err)
	}

	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action == "" {
		return w.failJob(jobID, fmt.Errorf("action required"))
	}

	spec, ok := actionSpecs[action]
	if !ok {
		return w.failJob(jobID, fmt.Errorf("unsupported action: %s", action))
	}
	if req.GetTopic() != topicRead {
		return w.failJob(jobID, fmt.Errorf("read actions require %s topic", topicRead))
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return w.failJob(jobID, err)
	}
	if err := enforceActionPolicy(profile, action); err != nil {
		return w.failJob(jobID, err)
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}
	if err := validateParams(params, spec.RequiredKeys); err != nil {
		return w.failJob(jobID, err)
	}

	client := promapi.NewClient(profile.BaseURL, promapi.Options{
		Headers:   profile.Headers,
		UserAgent: profile.UserAgent,
		Timeout:   w.requestTimeout(profile),
		Bearer:    resolveSecret(profile.Token, profile.TokenEnv),
		BasicUser: resolveSecret(profile.BasicUsername, profile.BasicUsernameEnv),
		BasicPass: resolveSecret(profile.BasicPassword, profile.BasicPasswordEnv),
	})

	callCtx, cancel := context.WithTimeout(ctx, w.requestTimeout(profile))
	defer cancel()

	start := time.Now()
	result, statusCode, err := w.execute(callCtx, client, spec, params)
	call := callResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     action,
		StatusCode: statusCode,
		RequestID:  strings.TrimSpace(input.RequestID),
		DurationMs: time.Since(start).Milliseconds(),
		Result:     result,
	}
	if err != nil {
		call.Error = err.Error()
	}
	return w.finishJob(jobID, call, err)
}

func (w *Worker) fetchInput(ctx context.Context, ptr string) (JobInput, error) {
	if ptr == "" {
		return JobInput{}, fmt.Errorf("context_ptr missing")
	}
	mem, err := w.gateway.GetMemory(ctx, ptr)
	if err != nil {
		return JobInput{}, err
	}
	payload, ok := mem.JSON.(map[string]any)
	if !ok {
		return JobInput{}, fmt.Errorf("unexpected context format")
	}
	if ctxPayload, ok := payload["context"].(map[string]any); ok {
		payload = ctxPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return JobInput{}, err
	}
	var input JobInput
	if err := json.Unmarshal(data, &input); err != nil {
		return JobInput{}, err
	}
	return input, nil
}

func (w *Worker) resolveProfile(name string) (config.Profile, error) {
	profileName := strings.TrimSpace(name)
	if profileName == "" {
		profileName = w.cfg.DefaultProfile
	}
	if profileName == "" {
		return config.Profile{}, fmt.Errorf("profile required")
	}
	profile, ok := w.cfg.Profiles[profileName]
	if !ok {
		return config.Profile{}, fmt.Errorf("unknown profile: %s", profileName)
	}
	if profile.Name == "" {
		profile.Name = profileName
	}
	return profile, nil
}

func (w *Worker) requestTimeout(profile config.Profile) time.Duration {
	if profile.Timeout > 0 {
		return profile.Timeout
	}
	return w.cfg.RequestTimeout
}

func (w *Worker) execute(ctx context.Context, client *promapi.Client, spec actionSpec, params map[string]any) (any, int, error) {
	path := spec.Path
	if spec.PathParam != "" {
		val := strings.TrimSpace(stringParam(params, spec.PathParam))
		if val == "" {
			return nil, 0, fmt.Errorf("%s required", spec.PathParam)
		}
		path = strings.ReplaceAll(path, "{"+spec.PathParam+"}", url.PathEscape(val))
	}

	query, err := buildQuery(params, spec)
	if err != nil {
		return nil, 0, err
	}

	resp, statusCode, err := client.Do(ctx, spec.Method, path, query)
	if resp == nil {
		return nil, statusCode, err
	}
	if err != nil {
		return resp, statusCode, err
	}
	return resp, statusCode, nil
}

func (w *Worker) finishJob(jobID string, result callResult, err error) (*agentv1.JobResult, error) {
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

func buildQuery(params map[string]any, spec actionSpec) (url.Values, error) {
	values := url.Values{}
	arrayKeys := map[string]struct{}{}
	for _, key := range spec.ArrayKeys {
		arrayKeys[key] = struct{}{}
	}

	for key, val := range params {
		if key == spec.PathParam {
			continue
		}
		if _, ok := arrayKeys[key]; ok {
			appendArray(values, "match[]", val)
			continue
		}
		if str, ok := toString(val); ok {
			values.Set(key, str)
		}
	}
	return values, nil
}

func appendArray(values url.Values, key string, val any) {
	switch typed := val.(type) {
	case []any:
		for _, item := range typed {
			if str, ok := toString(item); ok {
				values.Add(key, str)
			}
		}
	case []string:
		for _, item := range typed {
			if strings.TrimSpace(item) != "" {
				values.Add(key, item)
			}
		}
	default:
		if str, ok := toString(val); ok {
			values.Add(key, str)
		}
	}
}

func toString(val any) (string, bool) {
	switch typed := val.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return "", false
		}
		return typed, true
	case float64, float32, int, int64, int32, uint, uint64, uint32, bool:
		return fmt.Sprintf("%v", typed), true
	default:
		return "", false
	}
}

func validateParams(params map[string]any, required []string) error {
	for _, key := range required {
		val, ok := params[key]
		if !ok {
			return fmt.Errorf("%s required", key)
		}
		if str, ok := val.(string); ok && strings.TrimSpace(str) == "" {
			return fmt.Errorf("%s required", key)
		}
		if key == "match" {
			switch typed := val.(type) {
			case []any:
				if len(typed) == 0 {
					return fmt.Errorf("match required")
				}
			case []string:
				if len(typed) == 0 {
					return fmt.Errorf("match required")
				}
			}
		}
	}
	return nil
}

func enforceActionPolicy(profile config.Profile, action string) error {
	if len(profile.AllowActions) > 0 && !matchAny(profile.AllowActions, action) {
		return fmt.Errorf("action not allowed: %s", action)
	}
	if matchAny(profile.DenyActions, action) {
		return fmt.Errorf("action denied: %s", action)
	}
	return nil
}

func matchAny(patterns []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, pattern := range patterns {
		candidate := strings.ToLower(strings.TrimSpace(pattern))
		if candidate == "" {
			continue
		}
		if candidate == value {
			return true
		}
		if ok, _ := path.Match(candidate, value); ok {
			return true
		}
	}
	return false
}

func stringParam(params map[string]any, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func resolveSecret(raw, envKey string) string {
	if strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw)
	}
	if strings.TrimSpace(envKey) != "" {
		return strings.TrimSpace(os.Getenv(envKey))
	}
	return ""
}
