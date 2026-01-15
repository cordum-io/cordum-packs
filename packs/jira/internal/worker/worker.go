package worker

import (
	"context"
	"encoding/base64"
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

	"github.com/cordum-io/cordum-packs/packs/jira/internal/config"
	"github.com/cordum-io/cordum-packs/packs/jira/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/jira/internal/jiraapi"
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
	Username    string `json:"username"`
	UsernameEnv string `json:"username_env"`
	Token       string `json:"token"`
	TokenEnv    string `json:"token_env"`
	TokenType   string `json:"token_type"`
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
	Intent       string
	ParamsStyle  string
	RequiredKeys []string
	PathParams   []string
}

var actionSpecs = map[string]actionSpec{
	"issues.get":        {Name: "issues.get", Method: httpMethodGet, Path: "/rest/api/3/issue/{issue}", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"issue"}, PathParams: []string{"issue"}},
	"issues.search":     {Name: "issues.search", Method: httpMethodPost, Path: "/rest/api/3/search", Intent: "read", ParamsStyle: "json", RequiredKeys: []string{"jql"}},
	"projects.list":     {Name: "projects.list", Method: httpMethodGet, Path: "/rest/api/3/project/search", Intent: "read", ParamsStyle: "query"},
	"projects.get":      {Name: "projects.get", Method: httpMethodGet, Path: "/rest/api/3/project/{project}", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"project"}, PathParams: []string{"project"}},
	"users.get":         {Name: "users.get", Method: httpMethodGet, Path: "/rest/api/3/user", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"account_id|accountId"}},
	"fields.list":       {Name: "fields.list", Method: httpMethodGet, Path: "/rest/api/3/field", Intent: "read", ParamsStyle: "query"},
	"issuetypes.list":   {Name: "issuetypes.list", Method: httpMethodGet, Path: "/rest/api/3/issuetype", Intent: "read", ParamsStyle: "query"},
	"issues.create":     {Name: "issues.create", Method: httpMethodPost, Path: "/rest/api/3/issue", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"fields"}},
	"issues.transition": {Name: "issues.transition", Method: httpMethodPost, Path: "/rest/api/3/issue/{issue}/transitions", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"issue", "transition_id|transitionId|transition"}, PathParams: []string{"issue"}},
	"issues.comment":    {Name: "issues.comment", Method: httpMethodPost, Path: "/rest/api/3/issue/{issue}/comment", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"issue", "body"}, PathParams: []string{"issue"}},
	"issues.assign":     {Name: "issues.assign", Method: httpMethodPut, Path: "/rest/api/3/issue/{issue}/assignee", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"issue", "account_id|accountId"}, PathParams: []string{"issue"}},
	"issues.update":     {Name: "issues.update", Method: httpMethodPut, Path: "/rest/api/3/issue/{issue}", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"issue", "fields|update"}, PathParams: []string{"issue"}},
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
		Capabilities:    []string{"jira"},
		Labels:          map[string]string{"adapter": "jira"},
		Type:            "jira",
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

	projects := extractProjects(params)
	if err := enforceProjectPolicy(profile, projects); err != nil {
		return w.failJob(jobID, err)
	}

	authHeader, err := w.resolveAuth(profile, input.Auth)
	if err != nil {
		return w.failJob(jobID, err)
	}

	client := jiraapi.NewClient(profile.BaseURL, authHeader, jiraapi.Options{
		Headers:   profile.Headers,
		UserAgent: profile.UserAgent,
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

func (w *Worker) resolveAuth(profile config.Profile, inline InlineAuth) (string, error) {
	inlineProvided := inline.HasAny()
	if inlineProvided && !w.cfg.AllowInlineAuth {
		return "", fmt.Errorf("inline auth disabled")
	}

	username := resolveSecret(profile.Username, profile.UsernameEnv)
	token := resolveSecret(profile.Token, profile.TokenEnv)
	tokenType := strings.TrimSpace(profile.TokenType)
	if tokenType == "" {
		tokenType = "basic"
	}

	if inlineProvided {
		if inline.Username != "" || inline.UsernameEnv != "" {
			username = resolveSecret(inline.Username, inline.UsernameEnv)
		}
		if inline.Token != "" || inline.TokenEnv != "" {
			token = resolveSecret(inline.Token, inline.TokenEnv)
		}
		if inline.TokenType != "" {
			tokenType = strings.TrimSpace(inline.TokenType)
		}
	}

	switch strings.ToLower(tokenType) {
	case "basic":
		if username == "" || token == "" {
			return "", fmt.Errorf("jira basic auth requires username and token")
		}
		payload := base64.StdEncoding.EncodeToString([]byte(username + ":" + token))
		return "Basic " + payload, nil
	case "bearer":
		if token == "" {
			return "", fmt.Errorf("jira bearer auth requires token")
		}
		return "Bearer " + token, nil
	default:
		return "", fmt.Errorf("unsupported token type: %s", tokenType)
	}
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
		if topic != "job.jira.read" {
			return fmt.Errorf("read actions must use job.jira.read topic")
		}
	case "write":
		if topic != "job.jira.write" {
			return fmt.Errorf("write actions must use job.jira.write topic")
		}
	default:
		return fmt.Errorf("unknown action intent: %s", intent)
	}
	return nil
}

func (w *Worker) execute(ctx context.Context, client *jiraapi.Client, spec actionSpec, params map[string]any) (*jiraapi.Response, error) {
	pathValue, cleaned, err := resolvePath(spec.Path, params, spec.PathParams)
	if err != nil {
		return nil, err
	}

	requestParams := normalizeParams(cleaned)
	requestPath := spec.Path
	if pathValue != "" {
		requestPath = pathValue
	}

	switch spec.Name {
	case "issues.transition":
		body, err := buildTransitionBody(requestParams)
		if err != nil {
			return nil, err
		}
		return client.Do(ctx, spec.Method, requestPath, nil, body)
	case "issues.assign":
		body, err := buildAssignBody(requestParams)
		if err != nil {
			return nil, err
		}
		return client.Do(ctx, spec.Method, requestPath, nil, body)
	case "issues.comment", "issues.update", "issues.create":
		return client.Do(ctx, spec.Method, requestPath, nil, requestParams)
	default:
		if spec.ParamsStyle == "query" {
			return client.Do(ctx, spec.Method, requestPath, encodeQuery(requestParams), nil)
		}
		return client.Do(ctx, spec.Method, requestPath, nil, requestParams)
	}
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
		return "", params, nil
	}
	result := pathTemplate
	cleaned := copyMap(params)
	for _, param := range pathParams {
		value, key, ok := lookupParam(cleaned, param)
		if !ok {
			return "", nil, fmt.Errorf("missing required param: %s", param)
		}
		result = strings.ReplaceAll(result, "{"+param+"}", url.PathEscape(value))
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
	case "issue":
		return []string{"issue", "issue_key", "issueKey", "issue_id", "issueId"}
	case "project":
		return []string{"project", "project_key", "projectKey", "project_id", "projectId"}
	case "account_id":
		return []string{"account_id", "accountId", "user", "username"}
	default:
		return []string{key}
	}
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

func normalizeParams(params map[string]any) map[string]any {
	out := copyMap(params)
	if val, ok := out["account_id"]; ok {
		if _, exists := out["accountId"]; !exists {
			out["accountId"] = val
		}
		delete(out, "account_id")
	}
	return out
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

func buildTransitionBody(params map[string]any) (map[string]any, error) {
	body := map[string]any{}
	if transition, ok := params["transition"]; ok {
		switch value := transition.(type) {
		case map[string]any:
			body["transition"] = value
		case string:
			if strings.TrimSpace(value) != "" {
				body["transition"] = map[string]any{"id": strings.TrimSpace(value)}
			}
		}
	} else if transitionID, ok := params["transition_id"]; ok {
		if id, ok := coerceString(transitionID); ok {
			body["transition"] = map[string]any{"id": id}
		}
	} else if transitionID, ok := params["transitionId"]; ok {
		if id, ok := coerceString(transitionID); ok {
			body["transition"] = map[string]any{"id": id}
		}
	}
	if _, ok := body["transition"]; !ok {
		return nil, fmt.Errorf("transition id required")
	}
	if fields, ok := params["fields"]; ok {
		body["fields"] = fields
	}
	if update, ok := params["update"]; ok {
		body["update"] = update
	}
	return body, nil
}

func buildAssignBody(params map[string]any) (map[string]any, error) {
	if accountID, ok := params["accountId"]; ok {
		return map[string]any{"accountId": accountID}, nil
	}
	if accountID, ok := params["account_id"]; ok {
		return map[string]any{"accountId": accountID}, nil
	}
	return nil, fmt.Errorf("accountId required")
}

func extractProjects(params map[string]any) []string {
	projects := []string{}
	if project, ok := extractProjectParam(params); ok {
		projects = append(projects, project)
	}
	if issue, _, ok := lookupParam(params, "issue"); ok {
		if project := projectFromIssue(issue); project != "" {
			projects = append(projects, project)
		}
	}
	if fields, ok := params["fields"].(map[string]any); ok {
		if project, ok := extractProjectParam(fields); ok {
			projects = append(projects, project)
		}
		if projectMap, ok := fields["project"].(map[string]any); ok {
			if project, ok := extractProjectParam(projectMap); ok {
				projects = append(projects, project)
			}
		}
	}
	return uniqueStrings(projects)
}

func extractProjectParam(params map[string]any) (string, bool) {
	for _, key := range []string{"project", "project_key", "projectKey", "project_id", "projectId", "key"} {
		if value, ok := params[key]; ok {
			if str, ok := coerceString(value); ok {
				return str, true
			}
			if nested, ok := value.(map[string]any); ok {
				if project, ok := extractProjectParam(nested); ok {
					return project, true
				}
			}
		}
	}
	return "", false
}

func projectFromIssue(issue string) string {
	parts := strings.SplitN(strings.TrimSpace(issue), "-", 2)
	if len(parts) != 2 {
		return ""
	}
	if parts[0] == "" {
		return ""
	}
	return parts[0]
}

func enforceProjectPolicy(profile config.Profile, projects []string) error {
	if len(profile.AllowedProjects) == 0 && len(profile.DeniedProjects) == 0 {
		return nil
	}
	if len(projects) == 0 {
		return fmt.Errorf("project required for policy enforcement")
	}
	for _, project := range projects {
		if project == "" {
			continue
		}
		if len(profile.AllowedProjects) > 0 && !matchAny(profile.AllowedProjects, project) {
			return fmt.Errorf("project not allowed: %s", project)
		}
		if matchAny(profile.DeniedProjects, project) {
			return fmt.Errorf("project denied: %s", project)
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

func resolveSecret(value, envKey string) string {
	if strings.TrimSpace(envKey) != "" {
		return strings.TrimSpace(os.Getenv(envKey))
	}
	return strings.TrimSpace(value)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		val := strings.TrimSpace(value)
		if val == "" || seen[val] {
			continue
		}
		seen[val] = true
		out = append(out, val)
	}
	return out
}

func (a InlineAuth) HasAny() bool {
	return strings.TrimSpace(a.Username) != "" ||
		strings.TrimSpace(a.UsernameEnv) != "" ||
		strings.TrimSpace(a.Token) != "" ||
		strings.TrimSpace(a.TokenEnv) != "" ||
		strings.TrimSpace(a.TokenType) != ""
}
