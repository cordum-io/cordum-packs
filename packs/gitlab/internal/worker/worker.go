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

	"github.com/cordum-io/cordum-packs/packs/gitlab/internal/config"
	"github.com/cordum-io/cordum-packs/packs/gitlab/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/gitlab/internal/gitlabapi"
)

const (
	httpMethodGet  = "GET"
	httpMethodPost = "POST"
	httpMethodPut  = "PUT"
)

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
	Project    string `json:"project,omitempty"`
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

type actionSpec struct {
	Name            string
	Method          string
	Path            string
	Intent          string
	ParamsStyle     string
	RequiredKeys    []string
	PathParams      []string
	ProjectRequired bool
}

var actionSpecs = map[string]actionSpec{
	"projects.list":         {Name: "projects.list", Method: httpMethodGet, Path: "/projects", Intent: "read", ParamsStyle: "query"},
	"projects.get":          {Name: "projects.get", Method: httpMethodGet, Path: "/projects/{project}", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath"}, PathParams: []string{"project"}, ProjectRequired: true},
	"issues.list":           {Name: "issues.list", Method: httpMethodGet, Path: "/projects/{project}/issues", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath"}, PathParams: []string{"project"}, ProjectRequired: true},
	"issues.get":            {Name: "issues.get", Method: httpMethodGet, Path: "/projects/{project}/issues/{issue_iid}", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath", "issue_iid|issueIid|iid|issue"}, PathParams: []string{"project", "issue_iid"}, ProjectRequired: true},
	"merge_requests.list":   {Name: "merge_requests.list", Method: httpMethodGet, Path: "/projects/{project}/merge_requests", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath"}, PathParams: []string{"project"}, ProjectRequired: true},
	"merge_requests.get":    {Name: "merge_requests.get", Method: httpMethodGet, Path: "/projects/{project}/merge_requests/{merge_request_iid}", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath", "merge_request_iid|mergeRequestIid|iid|mr_iid"}, PathParams: []string{"project", "merge_request_iid"}, ProjectRequired: true},
	"pipelines.list":        {Name: "pipelines.list", Method: httpMethodGet, Path: "/projects/{project}/pipelines", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath"}, PathParams: []string{"project"}, ProjectRequired: true},
	"pipelines.get":         {Name: "pipelines.get", Method: httpMethodGet, Path: "/projects/{project}/pipelines/{pipeline_id}", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath", "pipeline_id|pipelineId|id"}, PathParams: []string{"project", "pipeline_id"}, ProjectRequired: true},
	"branches.list":         {Name: "branches.list", Method: httpMethodGet, Path: "/projects/{project}/repository/branches", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath"}, PathParams: []string{"project"}, ProjectRequired: true},
	"issues.create":         {Name: "issues.create", Method: httpMethodPost, Path: "/projects/{project}/issues", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath", "title"}, PathParams: []string{"project"}, ProjectRequired: true},
	"issues.update":         {Name: "issues.update", Method: httpMethodPut, Path: "/projects/{project}/issues/{issue_iid}", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath", "issue_iid|issueIid|iid|issue"}, PathParams: []string{"project", "issue_iid"}, ProjectRequired: true},
	"merge_requests.create": {Name: "merge_requests.create", Method: httpMethodPost, Path: "/projects/{project}/merge_requests", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath", "source_branch|sourceBranch", "target_branch|targetBranch", "title"}, PathParams: []string{"project"}, ProjectRequired: true},
	"merge_requests.update": {Name: "merge_requests.update", Method: httpMethodPut, Path: "/projects/{project}/merge_requests/{merge_request_iid}", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath", "merge_request_iid|mergeRequestIid|iid|mr_iid"}, PathParams: []string{"project", "merge_request_iid"}, ProjectRequired: true},
	"pipelines.run":         {Name: "pipelines.run", Method: httpMethodPost, Path: "/projects/{project}/pipeline", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"project|project_id|projectId|project_path|projectPath", "ref"}, PathParams: []string{"project"}, ProjectRequired: true},
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
		Capabilities:    []string{"gitlab"},
		Labels:          map[string]string{"adapter": "gitlab"},
		Type:            "gitlab",
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
	if err := w.enforceTopic(req.GetTopic(), spec.Intent); err != nil {
		return w.failJob(jobID, err)
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}
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

	project := ""
	if spec.ProjectRequired {
		project, err = extractProject(params)
		if err != nil {
			return w.failJob(jobID, err)
		}
		if err := enforceProjectPolicy(profile, project); err != nil {
			return w.failJob(jobID, err)
		}
	}

	token, tokenType, err := w.resolveAuth(profile, input.Auth)
	if err != nil {
		return w.failJob(jobID, err)
	}

	client := gitlabapi.NewClient(profile.BaseURL, token, gitlabapi.Options{
		Headers:   profile.Headers,
		UserAgent: profile.UserAgent,
		TokenType: tokenType,
		Timeout:   w.requestTimeout(profile),
	})

	callCtx, cancel := context.WithTimeout(ctx, w.requestTimeout(profile))
	defer cancel()

	start := time.Now()
	response, err := w.execute(callCtx, client, spec, params)

	result := callResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     spec.Name,
		Project:    project,
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

func (w *Worker) resolveAuth(profile config.Profile, inline InlineAuth) (string, string, error) {
	inlineProvided := inline.HasAny()
	if inlineProvided && !w.cfg.AllowInlineAuth {
		return "", "", fmt.Errorf("inline auth disabled")
	}

	token := resolveSecret(profile.Token, profile.TokenEnv)
	tokenType := strings.TrimSpace(profile.TokenType)
	if tokenType == "" {
		tokenType = "private"
	}

	if inlineProvided {
		if inline.Token != "" || inline.TokenEnv != "" {
			token = resolveSecret(inline.Token, inline.TokenEnv)
		}
		if inline.TokenType != "" {
			tokenType = strings.TrimSpace(inline.TokenType)
		}
	}

	if token == "" {
		return "", "", fmt.Errorf("gitlab token required")
	}
	return token, tokenType, nil
}

func (w *Worker) requestTimeout(profile config.Profile) time.Duration {
	if profile.Timeout > 0 {
		return profile.Timeout
	}
	return w.cfg.RequestTimeout
}

func (w *Worker) enforceTopic(topic, intent string) error {
	if topic == "" {
		return fmt.Errorf("job topic missing")
	}
	switch intent {
	case "read":
		if topic != "job.gitlab.read" {
			return fmt.Errorf("read actions must use job.gitlab.read topic")
		}
	case "write":
		if topic != "job.gitlab.write" {
			return fmt.Errorf("write actions must use job.gitlab.write topic")
		}
	default:
		return fmt.Errorf("unknown action intent: %s", intent)
	}
	return nil
}

func (w *Worker) execute(ctx context.Context, client *gitlabapi.Client, spec actionSpec, params map[string]any) (*gitlabapi.Response, error) {
	pathValue, cleaned, err := resolvePath(spec.Path, params, spec.PathParams)
	if err != nil {
		return nil, err
	}

	cleaned = normalizeParams(cleaned)
	if spec.ParamsStyle == "query" {
		return client.Do(ctx, spec.Method, pathValue, encodeQuery(cleaned), nil)
	}
	return client.Do(ctx, spec.Method, pathValue, nil, cleaned)
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
		escaped := value
		if param == "project" {
			escaped = escapeProject(value)
		} else {
			escaped = url.PathEscape(value)
		}
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
	case "project":
		return []string{"project", "project_id", "projectId", "project_path", "projectPath", "project_path_with_namespace"}
	case "issue_iid":
		return []string{"issue_iid", "issueIid", "iid", "issue", "issue_id", "issueId"}
	case "merge_request_iid":
		return []string{"merge_request_iid", "mergeRequestIid", "iid", "mr_iid", "merge_request", "mergeRequest"}
	case "pipeline_id":
		return []string{"pipeline_id", "pipelineId", "id"}
	default:
		return []string{key}
	}
}

func normalizeParams(params map[string]any) map[string]any {
	out := copyMap(params)
	copyParam(out, "projectId", "project_id")
	copyParam(out, "projectPath", "project_path")
	copyParam(out, "issueIid", "issue_iid")
	copyParam(out, "mergeRequestIid", "merge_request_iid")
	copyParam(out, "pipelineId", "pipeline_id")
	copyParam(out, "sourceBranch", "source_branch")
	copyParam(out, "targetBranch", "target_branch")
	return out
}

func copyParam(params map[string]any, from, to string) {
	if val, ok := params[from]; ok {
		if _, exists := params[to]; !exists {
			params[to] = val
		}
	}
}

func encodeQuery(params map[string]any) url.Values {
	values := url.Values{}
	for key, value := range params {
		if strings.TrimSpace(key) == "" {
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

func joinAny(values []any) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%v", value))
	}
	return strings.Join(parts, ",")
}

func extractProject(params map[string]any) (string, error) {
	for _, key := range paramAliases("project") {
		if value, ok := params[key]; ok {
			if str, ok := coerceString(value); ok {
				return str, nil
			}
		}
	}
	return "", fmt.Errorf("project required")
}

func enforceProjectPolicy(profile config.Profile, project string) error {
	if len(profile.AllowedProjects) == 0 && len(profile.DeniedProjects) == 0 {
		return nil
	}
	if strings.TrimSpace(project) == "" {
		return fmt.Errorf("project required for policy enforcement")
	}
	if len(profile.AllowedProjects) > 0 && !matchAny(profile.AllowedProjects, project) {
		return fmt.Errorf("project not allowed: %s", project)
	}
	if matchAny(profile.DeniedProjects, project) {
		return fmt.Errorf("project denied: %s", project)
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

func copyMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func escapeProject(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	escaped := url.PathEscape(trimmed)
	return strings.ReplaceAll(escaped, "/", "%2F")
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
