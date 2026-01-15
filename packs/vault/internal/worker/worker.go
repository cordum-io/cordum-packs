package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/vault/internal/config"
	"github.com/cordum-io/cordum-packs/packs/vault/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/vault/internal/vaultapi"
)

const httpMethodGet = "GET"

type Worker struct {
	cfg     config.Config
	gateway *gatewayclient.Client
	redis   *redis.Client
	worker  *runtime.Worker
}

type InlineAuth struct {
	Token     string `json:"token"`
	TokenEnv  string `json:"token_env"`
	TokenType string `json:"token_type"`
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
	Path       string `json:"path,omitempty"`
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

type actionSpec struct {
	Name          string
	Method        string
	Path          string
	ParamsStyle   string
	RequiredKeys  []string
	PathParams    []string
	QueryDefaults map[string]string
	PathRequired  bool
	KVList        bool
}

var actionSpecs = map[string]actionSpec{
	"secrets.read":         {Name: "secrets.read", Method: httpMethodGet, Path: "/{path}", ParamsStyle: "query", RequiredKeys: []string{"path|secret|secret_path|secretPath"}, PathParams: []string{"path"}, PathRequired: true},
	"secrets.list":         {Name: "secrets.list", Method: httpMethodGet, Path: "/{path}", ParamsStyle: "query", RequiredKeys: []string{"path|secret|secret_path|secretPath"}, PathParams: []string{"path"}, PathRequired: true, KVList: true, QueryDefaults: map[string]string{"list": "true"}},
	"auth.token.lookup":    {Name: "auth.token.lookup", Method: httpMethodGet, Path: "/auth/token/lookup-self", ParamsStyle: "query"},
	"credentials.generate": {Name: "credentials.generate", Method: httpMethodGet, Path: "/{path}", ParamsStyle: "query", RequiredKeys: []string{"path|secret|secret_path|secretPath"}, PathParams: []string{"path"}, PathRequired: true},
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
		Capabilities:    []string{"vault"},
		Labels:          map[string]string{"adapter": "vault"},
		Type:            "vault",
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
	if err := validateInlineAuth(input.Auth, w.cfg.AllowInlineAuth); err != nil {
		return w.failJob(jobID, err)
	}

	actionKey := strings.ToLower(strings.TrimSpace(input.Action))
	if actionKey == "" {
		return w.failJob(jobID, fmt.Errorf("action required"))
	}

	spec, ok := actionSpecs[actionKey]
	if !ok {
		return w.failJob(jobID, fmt.Errorf("unsupported action: %s", actionKey))
	}
	if req.GetTopic() != "job.vault.read" {
		return w.failJob(jobID, fmt.Errorf("read actions must use job.vault.read topic"))
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}
	params = normalizeParams(params)
	if err := validateParams(params, spec.RequiredKeys); err != nil {
		return w.failJob(jobID, err)
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return w.failJob(jobID, err)
	}
	if err := enforceActionPolicy(profile, spec.Name); err != nil {
		return w.failJob(jobID, err)
	}

	requestedPath := ""
	if spec.PathRequired {
		requestedPath, err = extractPath(params)
		if err != nil {
			return w.failJob(jobID, err)
		}
		if err := validatePath(requestedPath); err != nil {
			return w.failJob(jobID, err)
		}
		if err := enforcePathPolicy(profile, requestedPath); err != nil {
			return w.failJob(jobID, err)
		}
	}

	token, tokenType, namespace, err := w.resolveAuth(profile, input.Auth)
	if err != nil {
		return w.failJob(jobID, err)
	}

	client := vaultapi.NewClient(profile.BaseURL, token, vaultapi.Options{
		Headers:   profile.Headers,
		UserAgent: profile.UserAgent,
		TokenType: tokenType,
		Namespace: namespace,
		Timeout:   w.requestTimeout(profile),
	})

	callCtx, cancel := context.WithTimeout(ctx, w.requestTimeout(profile))
	defer cancel()

	start := time.Now()
	response, resolvedPath, err := w.execute(callCtx, client, spec, params)

	result := callResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     spec.Name,
		Path:       resolvedPath,
		DurationMs: time.Since(start).Milliseconds(),
	}
	if response != nil {
		result.StatusCode = response.StatusCode
		result.RequestID = response.RequestID
		result.Result = response.Body
	}
	if result.RequestID == "" && strings.TrimSpace(input.RequestID) != "" {
		result.RequestID = strings.TrimSpace(input.RequestID)
	}
	if err != nil {
		result.Error = err.Error()
	}
	return w.finishJob(jobID, result, err)
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

func (w *Worker) resolveAuth(profile config.Profile, inline InlineAuth) (string, string, string, error) {
	inlineProvided := inline.HasAny()
	if inlineProvided && !w.cfg.AllowInlineAuth {
		return "", "", "", fmt.Errorf("inline auth disabled")
	}

	token := resolveSecret(profile.Token, profile.TokenEnv)
	tokenType := strings.TrimSpace(profile.TokenType)
	if tokenType == "" {
		tokenType = "vault"
	}
	namespace := resolveSecret(profile.Namespace, profile.NamespaceEnv)

	if inlineProvided {
		if inline.Token != "" || inline.TokenEnv != "" {
			token = resolveSecret(inline.Token, inline.TokenEnv)
		}
		if inline.TokenType != "" {
			tokenType = strings.TrimSpace(inline.TokenType)
		}
	}

	if token == "" {
		return "", "", "", fmt.Errorf("vault token required")
	}
	return token, tokenType, namespace, nil
}

func (w *Worker) requestTimeout(profile config.Profile) time.Duration {
	if profile.Timeout > 0 {
		return profile.Timeout
	}
	return w.cfg.RequestTimeout
}

func (w *Worker) execute(ctx context.Context, client *vaultapi.Client, spec actionSpec, params map[string]any) (*vaultapi.Response, string, error) {
	pathValue, cleaned, err := resolvePath(spec.Path, params, spec.PathParams)
	if err != nil {
		return nil, "", err
	}

	resolvedPath := pathValue
	if spec.PathRequired {
		kvVersion := kvVersionFromParams(cleaned)
		resolvedPath = resolveSecretPath(pathValue, kvVersion, spec.KVList)
	}

	cleaned = stripKeys(cleaned, []string{"kv_version", "kv_v2"})
	query := encodeQuery(cleaned, spec.QueryDefaults)
	resp, err := client.Do(ctx, spec.Method, resolvedPath, query, nil)
	return resp, resolvedPath, err
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

func validateInlineAuth(auth InlineAuth, allowed bool) error {
	if auth.HasAny() && !allowed {
		return fmt.Errorf("inline auth disabled")
	}
	return nil
}

func validateParams(params map[string]any, required []string) error {
	for _, key := range required {
		alternatives := strings.Split(key, "|")
		found := false
		for _, alt := range alternatives {
			if hasParam(params, alt) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing required param: %s", key)
		}
	}
	return nil
}

func hasParam(params map[string]any, key string) bool {
	value, ok := params[key]
	if !ok {
		return false
	}
	switch val := value.(type) {
	case string:
		return strings.TrimSpace(val) != ""
	case []any:
		return len(val) > 0
	case []string:
		return len(val) > 0
	default:
		return true
	}
}

func resolvePath(pathTemplate string, params map[string]any, pathParams []string) (string, map[string]any, error) {
	if len(pathParams) == 0 {
		return pathTemplate, params, nil
	}
	result := pathTemplate
	cleaned := copyMap(params)
	for _, param := range pathParams {
		value, key, ok := lookupParam(cleaned, param)
		if !ok {
			return "", nil, fmt.Errorf("missing required param: %s", param)
		}
		escaped := url.PathEscape(strings.TrimPrefix(value, "/"))
		result = strings.ReplaceAll(result, "{"+param+"}", escaped)
		delete(cleaned, key)
	}
	return result, cleaned, nil
}

func lookupParam(params map[string]any, key string) (string, string, bool) {
	aliases := paramAliases(key)
	for _, alias := range aliases {
		value, ok := params[alias]
		if !ok {
			continue
		}
		if str, ok := coerceString(value); ok {
			return str, alias, true
		}
	}
	return "", "", false
}

func paramAliases(key string) []string {
	switch key {
	case "path":
		return []string{"path", "secret", "secret_path", "secretPath"}
	default:
		return []string{key}
	}
}

func normalizeParams(params map[string]any) map[string]any {
	out := copyMap(params)
	copyParam(out, "secretPath", "secret_path")
	copyParam(out, "secret", "path")
	copyParam(out, "secret_path", "path")
	copyParam(out, "kvVersion", "kv_version")
	copyParam(out, "kvV2", "kv_v2")
	return out
}

func copyParam(params map[string]any, from, to string) {
	if val, ok := params[from]; ok {
		if _, exists := params[to]; !exists {
			params[to] = val
		}
	}
}

func extractPath(params map[string]any) (string, error) {
	for _, key := range paramAliases("path") {
		if value, ok := params[key]; ok {
			if str, ok := coerceString(value); ok {
				return str, nil
			}
		}
	}
	return "", fmt.Errorf("path required")
}

func validatePath(pathValue string) error {
	trimmed := strings.TrimSpace(pathValue)
	if trimmed == "" {
		return fmt.Errorf("path required")
	}
	if strings.Contains(trimmed, "..") {
		return fmt.Errorf("invalid path: %s", trimmed)
	}
	return nil
}

func kvVersionFromParams(params map[string]any) int {
	if val, ok := params["kv_version"]; ok {
		if num, ok := coerceInt(val); ok {
			return num
		}
	}
	if val, ok := params["kv_v2"]; ok {
		switch typed := val.(type) {
		case bool:
			if typed {
				return 2
			}
		case string:
			if strings.EqualFold(strings.TrimSpace(typed), "true") {
				return 2
			}
		}
	}
	return 0
}

func resolveSecretPath(raw string, kvVersion int, list bool) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return "/"
	}
	if kvVersion != 2 {
		return "/" + trimmed
	}
	if strings.Contains(trimmed, "/data/") || strings.Contains(trimmed, "/metadata/") {
		return "/" + trimmed
	}
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 {
		return "/" + trimmed
	}
	segment := "data"
	if list {
		segment = "metadata"
	}
	return "/" + parts[0] + "/" + segment + "/" + parts[1]
}

func encodeQuery(params map[string]any, defaults map[string]string) url.Values {
	values := url.Values{}
	for key, value := range defaults {
		values.Set(key, value)
	}
	for key, value := range params {
		if strings.TrimSpace(key) == "" {
			continue
		}
		if _, ok := defaults[key]; ok {
			continue
		}
		switch val := value.(type) {
		case string:
			values.Set(key, val)
		case bool:
			values.Set(key, strconv.FormatBool(val))
		case float64:
			values.Set(key, strconv.FormatFloat(val, 'f', -1, 64))
		case int:
			values.Set(key, strconv.Itoa(val))
		case int64:
			values.Set(key, strconv.FormatInt(val, 10))
		case []string:
			values.Set(key, strings.Join(val, ","))
		case []any:
			values.Set(key, joinAny(val))
		default:
			values.Set(key, fmt.Sprintf("%v", val))
		}
	}
	return values
}

func stripKeys(params map[string]any, keys []string) map[string]any {
	if len(keys) == 0 {
		return params
	}
	out := copyMap(params)
	for _, key := range keys {
		delete(out, key)
	}
	return out
}

func joinAny(values []any) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%v", value))
	}
	return strings.Join(parts, ",")
}

func enforcePathPolicy(profile config.Profile, pathValue string) error {
	if len(profile.AllowedPaths) == 0 && len(profile.DeniedPaths) == 0 {
		return nil
	}
	value := normalizePolicyPath(pathValue)
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("path required for policy enforcement")
	}
	if len(profile.AllowedPaths) > 0 && !matchAny(profile.AllowedPaths, value) {
		return fmt.Errorf("path not allowed: %s", value)
	}
	if matchAny(profile.DeniedPaths, value) {
		return fmt.Errorf("path denied: %s", value)
	}
	return nil
}

func normalizePolicyPath(value string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "/")
	trimmed = strings.ReplaceAll(trimmed, "/data/", "/")
	trimmed = strings.ReplaceAll(trimmed, "/metadata/", "/")
	return trimmed
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

func coerceString(value any) (string, bool) {
	switch val := value.(type) {
	case string:
		trimmed := strings.TrimSpace(val)
		if trimmed == "" {
			return "", false
		}
		return trimmed, true
	case fmt.Stringer:
		trimmed := strings.TrimSpace(val.String())
		if trimmed == "" {
			return "", false
		}
		return trimmed, true
	case int:
		return fmt.Sprintf("%d", val), true
	case int64:
		return fmt.Sprintf("%d", val), true
	case float64:
		return fmt.Sprintf("%v", val), true
	default:
		return "", false
	}
}

func coerceInt(value any) (int, bool) {
	switch val := value.(type) {
	case int:
		return val, true
	case int64:
		return int(val), true
	case float64:
		return int(val), true
	case string:
		if num, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			return num, true
		}
	}
	return 0, false
}

func copyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func resolveSecret(value, envKey string) string {
	if strings.TrimSpace(envKey) != "" {
		if envVal := strings.TrimSpace(os.Getenv(envKey)); envVal != "" {
			return envVal
		}
	}
	return strings.TrimSpace(value)
}

func (a InlineAuth) HasAny() bool {
	return strings.TrimSpace(a.Token) != "" ||
		strings.TrimSpace(a.TokenEnv) != "" ||
		strings.TrimSpace(a.TokenType) != ""
}
