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

	"github.com/cordum-io/cordum-packs/packs/pagerduty/internal/config"
	"github.com/cordum-io/cordum-packs/packs/pagerduty/internal/pagerdutyapi"
)

const (
	topicRead  = "job.pagerduty.read"
	topicWrite = "job.pagerduty.write"
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
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "pagerduty")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
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

	client := pagerdutyapi.NewClient(profile.BaseURL, pagerdutyapi.Options{
		Token:     resolveSecret(profile.Token, profile.TokenEnv),
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
