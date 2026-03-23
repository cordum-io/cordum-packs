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
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/datadog/internal/config"
	"github.com/cordum-io/cordum-packs/packs/datadog/internal/datadogapi"
)

const (
	topicRead  = "job.datadog.read"
	topicWrite = "job.datadog.write"
)

type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
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
	Topic        string
	Method       string
	Path         string
	RequiredKeys []string
	PathParam    string
	QueryKeys    []string
	Body         bool
}

var actionSpecs = map[string]actionSpec{
	"metrics.query":   {Name: "metrics.query", Topic: topicRead, Method: http.MethodGet, Path: "/api/v1/query", RequiredKeys: []string{"from", "to", "query"}},
	"logs.search":     {Name: "logs.search", Topic: topicRead, Method: http.MethodPost, Path: "/api/v2/logs/events/search", Body: true},
	"traces.search":   {Name: "traces.search", Topic: topicRead, Method: http.MethodPost, Path: "/api/v2/apm/events/search", Body: true},
	"monitors.list":   {Name: "monitors.list", Topic: topicRead, Method: http.MethodGet, Path: "/api/v1/monitor"},
	"monitors.get":    {Name: "monitors.get", Topic: topicRead, Method: http.MethodGet, Path: "/api/v1/monitor/{id}", PathParam: "id"},
	"monitors.mute":   {Name: "monitors.mute", Topic: topicWrite, Method: http.MethodPost, Path: "/api/v1/monitor/{id}/mute", PathParam: "id", Body: true},
	"monitors.unmute": {Name: "monitors.unmute", Topic: topicWrite, Method: http.MethodPost, Path: "/api/v1/monitor/{id}/unmute", PathParam: "id", QueryKeys: []string{"scope"}},
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "datadog")
	natsOpts := []nats.Option{nats.Name(workerID), nats.Timeout(5 * time.Second)}
	if tlsCfg, tlsErr := runtime.NATSTLSConfigFromEnv(); tlsErr != nil {
		return nil, fmt.Errorf("nats tls config: %w", tlsErr)
	} else if tlsCfg != nil {
		natsOpts = append(natsOpts, nats.Secure(tlsCfg))
	}
	nc, err := nats.Connect(cfg.NatsURL, natsOpts...)
	if err != nil {
		return nil, err
	}
	store, err := runtime.NewRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
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
		subjects = []string{topicRead, topicWrite}
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

	jobID := ctx.Job.GetJobId()
	payload = normalizePayload(payload)

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		return callResult{}, err
	}

	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action == "" {
		return callResult{}, fmt.Errorf("action required")
	}

	spec, ok := actionSpecs[action]
	if !ok {
		return callResult{}, fmt.Errorf("unsupported action: %s", action)
	}
	if ctx.Job.GetTopic() != spec.Topic {
		return callResult{}, fmt.Errorf("action %s requires %s topic", action, spec.Topic)
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return callResult{}, err
	}
	if err := enforceActionPolicy(profile, action); err != nil {
		return callResult{}, err
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}
	if err := validateParams(params, spec.RequiredKeys); err != nil {
		return callResult{}, err
	}

	client := datadogapi.NewClient(profile.BaseURL, datadogapi.Options{
		APIKey:    resolveSecret(profile.APIKey, profile.APIKeyEnv),
		AppKey:    resolveSecret(profile.AppKey, profile.AppKeyEnv),
		Headers:   profile.Headers,
		UserAgent: profile.UserAgent,
		Timeout:   w.requestTimeout(profile),
	})

	callCtx, cancel := context.WithTimeout(context.Background(), w.requestTimeout(profile))
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
	return call, err
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

func (w *Worker) execute(ctx context.Context, client *datadogapi.Client, spec actionSpec, params map[string]any) (any, int, error) {
	path := spec.Path
	if spec.PathParam != "" {
		val := strings.TrimSpace(stringParam(params, spec.PathParam))
		if val == "" {
			return nil, 0, fmt.Errorf("%s required", spec.PathParam)
		}
		path = strings.ReplaceAll(path, "{"+spec.PathParam+"}", url.PathEscape(val))
	}

	query, body, err := splitParams(params, spec)
	if err != nil {
		return nil, 0, err
	}

	return client.Do(ctx, spec.Method, path, query, body)
}

func splitParams(params map[string]any, spec actionSpec) (url.Values, map[string]any, error) {
	query := url.Values{}
	body := map[string]any{}
	queryKeys := map[string]struct{}{}
	for _, key := range spec.QueryKeys {
		queryKeys[key] = struct{}{}
	}

	for key, val := range params {
		if key == spec.PathParam {
			continue
		}
		if spec.Method == http.MethodGet || spec.Method == http.MethodDelete {
			if err := addQueryValue(query, key, val); err != nil {
				return nil, nil, err
			}
			continue
		}
		if _, ok := queryKeys[key]; ok {
			if err := addQueryValue(query, key, val); err != nil {
				return nil, nil, err
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
	return query, body, nil
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
		joined := joinList(typed)
		if joined != "" {
			values.Set(key, joined)
		}
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := toString(item); ok {
				parts = append(parts, str)
			}
		}
		if len(parts) > 0 {
			values.Set(key, strings.Join(parts, ","))
		}
	case float64, float32, int, int64, int32, uint, uint64, uint32, bool:
		values.Set(key, fmt.Sprintf("%v", typed))
	default:
		return fmt.Errorf("unsupported query value for %s", key)
	}
	return nil
}

func joinList(values []string) string {
	parts := make([]string, 0, len(values))
	for _, item := range values {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, ",")
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
