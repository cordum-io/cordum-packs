package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/prometheus-query/internal/config"
	"github.com/cordum-io/cordum-packs/packs/prometheus-query/internal/promapi"
)

const topicRead = "job.prometheus-query.read"

type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
}

type InlineAuth struct {
	Token            string `json:"token"`
	TokenEnv         string `json:"token_env"`
	BasicUsername    string `json:"basic_username"`
	BasicUsernameEnv string `json:"basic_username_env"`
	BasicPassword    string `json:"basic_password"`
	BasicPasswordEnv string `json:"basic_password_env"`
}

type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
	Auth      InlineAuth     `json:"auth"`
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
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := runtime.ResolveWorkerID("", "prometheus")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
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
		subjects = []string{topicRead}
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
	if err := validateInlineAuth(input.Auth, w.cfg.AllowInlineAuth, w.cfg.AllowInlineSecrets); err != nil {
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
	if ctx.Job.GetTopic() != topicRead {
		return callResult{}, fmt.Errorf("read actions require %s topic", topicRead)
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

	bearer, basicUser, basicPass, err := w.resolveAuth(profile, input.Auth)
	if err != nil {
		return callResult{}, err
	}

	client := promapi.NewClient(profile.BaseURL, promapi.Options{
		Headers:   profile.Headers,
		UserAgent: profile.UserAgent,
		Timeout:   w.requestTimeout(profile),
		Bearer:    bearer,
		BasicUser: basicUser,
		BasicPass: basicPass,
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

func (w *Worker) resolveAuth(profile config.Profile, inline InlineAuth) (string, string, string, error) {
	if inline.HasAny() && !w.cfg.AllowInlineAuth {
		return "", "", "", fmt.Errorf("inline auth disabled")
	}
	if inline.HasSecrets() && !w.cfg.AllowInlineSecrets {
		return "", "", "", fmt.Errorf("inline secrets disabled; use *_env fields")
	}

	bearer := resolveSecret(profile.Token, profile.TokenEnv)
	basicUser := resolveSecret(profile.BasicUsername, profile.BasicUsernameEnv)
	basicPass := resolveSecret(profile.BasicPassword, profile.BasicPasswordEnv)

	if inline.HasAny() {
		if inline.Token != "" || inline.TokenEnv != "" {
			bearer = resolveSecret(inline.Token, inline.TokenEnv)
		}
		if inline.BasicUsername != "" || inline.BasicUsernameEnv != "" {
			basicUser = resolveSecret(inline.BasicUsername, inline.BasicUsernameEnv)
		}
		if inline.BasicPassword != "" || inline.BasicPasswordEnv != "" {
			basicPass = resolveSecret(inline.BasicPassword, inline.BasicPasswordEnv)
		}
	}

	return bearer, basicUser, basicPass, nil
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
	if strings.TrimSpace(envKey) != "" {
		if envVal := strings.TrimSpace(os.Getenv(envKey)); envVal != "" {
			return envVal
		}
	}
	return strings.TrimSpace(raw)
}

func validateInlineAuth(auth InlineAuth, allowed, allowSecrets bool) error {
	if auth.HasAny() && !allowed {
		return fmt.Errorf("inline auth disabled")
	}
	if auth.HasSecrets() && !allowSecrets {
		return fmt.Errorf("inline secrets disabled; use *_env fields")
	}
	return nil
}

func (a InlineAuth) HasAny() bool {
	return strings.TrimSpace(a.Token) != "" ||
		strings.TrimSpace(a.TokenEnv) != "" ||
		strings.TrimSpace(a.BasicUsername) != "" ||
		strings.TrimSpace(a.BasicUsernameEnv) != "" ||
		strings.TrimSpace(a.BasicPassword) != "" ||
		strings.TrimSpace(a.BasicPasswordEnv) != ""
}

func (a InlineAuth) HasSecrets() bool {
	return strings.TrimSpace(a.Token) != "" || strings.TrimSpace(a.BasicPassword) != ""
}
