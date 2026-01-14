package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/pagerduty/internal/config"
	"github.com/cordum-io/cordum-packs/packs/pagerduty/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/pagerduty/internal/pagerdutyapi"
)

const (
	topicRead  = "job.pagerduty.read"
	topicWrite = "job.pagerduty.write"
)

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
	Name           string
	Topic          string
	Method         string
	Path           string
	RequiredKeys   []string
	PathParam      string
	HeaderParams   map[string]string
	IncidentStatus string
	Body           bool
}

var actionSpecs = map[string]actionSpec{
	"incidents.list":        {Name: "incidents.list", Topic: topicRead, Method: http.MethodGet, Path: "/incidents"},
	"incidents.get":         {Name: "incidents.get", Topic: topicRead, Method: http.MethodGet, Path: "/incidents/{id}", PathParam: "id", RequiredKeys: []string{"id"}},
	"oncalls.list":          {Name: "oncalls.list", Topic: topicRead, Method: http.MethodGet, Path: "/oncalls"},
	"schedules.list":        {Name: "schedules.list", Topic: topicRead, Method: http.MethodGet, Path: "/schedules"},
	"schedules.get":         {Name: "schedules.get", Topic: topicRead, Method: http.MethodGet, Path: "/schedules/{id}", PathParam: "id", RequiredKeys: []string{"id"}},
	"incidents.acknowledge": {Name: "incidents.acknowledge", Topic: topicWrite, Method: http.MethodPut, Path: "/incidents/{id}", PathParam: "id", RequiredKeys: []string{"id", "from"}, HeaderParams: map[string]string{"from": "From"}, IncidentStatus: "acknowledged"},
	"incidents.resolve":     {Name: "incidents.resolve", Topic: topicWrite, Method: http.MethodPut, Path: "/incidents/{id}", PathParam: "id", RequiredKeys: []string{"id", "from"}, HeaderParams: map[string]string{"from": "From"}, IncidentStatus: "resolved"},
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
		Capabilities:    []string{"pagerduty"},
		Labels:          map[string]string{"adapter": "pagerduty"},
		Type:            "pagerduty",
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
	if req.GetTopic() != spec.Topic {
		return w.failJob(jobID, fmt.Errorf("action %s requires %s topic", action, spec.Topic))
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

	client := pagerdutyapi.NewClient(profile.BaseURL, pagerdutyapi.Options{
		Token:     resolveSecret(profile.Token, profile.TokenEnv),
		Headers:   profile.Headers,
		UserAgent: profile.UserAgent,
		Timeout:   w.requestTimeout(profile),
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

func (w *Worker) execute(ctx context.Context, client *pagerdutyapi.Client, spec actionSpec, params map[string]any) (any, int, error) {
	path := spec.Path
	if spec.PathParam != "" {
		val := strings.TrimSpace(stringParam(params, spec.PathParam))
		if val == "" {
			return nil, 0, fmt.Errorf("%s required", spec.PathParam)
		}
		path = strings.ReplaceAll(path, "{"+spec.PathParam+"}", url.PathEscape(val))
	}

	query, body, headers, err := splitParams(params, spec)
	if err != nil {
		return nil, 0, err
	}
	if spec.IncidentStatus != "" {
		body = buildIncidentBody(spec.IncidentStatus, params)
	}

	return client.Do(ctx, spec.Method, path, query, body, headers)
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

func splitParams(params map[string]any, spec actionSpec) (url.Values, map[string]any, map[string]string, error) {
	query := url.Values{}
	body := map[string]any{}
	headers := map[string]string{}

	for key, val := range params {
		if key == spec.PathParam {
			continue
		}
		if headerName, ok := spec.HeaderParams[key]; ok {
			if str, ok := toString(val); ok {
				headers[headerName] = str
			}
			continue
		}
		if spec.Method == http.MethodGet || spec.Method == http.MethodDelete {
			if err := addQueryValue(query, key, val); err != nil {
				return nil, nil, nil, err
			}
			continue
		}
		if spec.Body {
			body[key] = val
		}
	}

	if !spec.Body {
		body = nil
	}
	return query, body, headers, nil
}

func addQueryValue(values url.Values, key string, val any) error {
	if strings.TrimSpace(key) == "" {
		return nil
	}
	switch typed := val.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed != "" {
			values.Set(key, trimmed)
		}
	case []string:
		for _, item := range typed {
			trimmed := strings.TrimSpace(item)
			if trimmed != "" {
				values.Add(key, trimmed)
			}
		}
	case []any:
		for _, item := range typed {
			if str, ok := toString(item); ok {
				values.Add(key, str)
			}
		}
	case float64, float32, int, int64, int32, uint, uint64, uint32, bool:
		values.Set(key, fmt.Sprintf("%v", typed))
	default:
		return fmt.Errorf("unsupported query value for %s", key)
	}
	return nil
}

func buildIncidentBody(status string, params map[string]any) map[string]any {
	if raw, ok := params["body"].(map[string]any); ok {
		return raw
	}
	incident := map[string]any{
		"type":   "incident_reference",
		"status": status,
	}
	if raw, ok := params["incident"].(map[string]any); ok {
		for key, val := range raw {
			incident[key] = val
		}
	}
	return map[string]any{"incident": incident}
}

func toString(val any) (string, bool) {
	switch typed := val.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return "", false
		}
		return trimmed, true
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
		switch typed := val.(type) {
		case []any:
			if len(typed) == 0 {
				return fmt.Errorf("%s required", key)
			}
		case []string:
			if len(typed) == 0 {
				return fmt.Errorf("%s required", key)
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
