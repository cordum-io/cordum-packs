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

	"github.com/cordum-io/cordum-packs/packs/github/internal/config"
	"github.com/cordum-io/cordum-packs/packs/github/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/github/internal/githubapi"
)

const (
	actionReposGet      = "repos.get"
	actionIssuesGet     = "issues.get"
	actionIssuesList    = "issues.list"
	actionIssuesCreate  = "issues.create"
	actionIssuesComment = "issues.comment"
	actionPullsGet      = "pulls.get"
	actionPullsCreate   = "pulls.create"
	actionSearchIssues  = "search.issues"
	actionContentsGet   = "contents.get"
)

type Worker struct {
	cfg     config.Config
	gateway *gatewayclient.Client
	redis   *redis.Client
	worker  *runtime.Worker
}

type InlineAuth struct {
	Token             string `json:"token"`
	TokenEnv          string `json:"token_env"`
	AppID             string `json:"app_id"`
	AppIDEnv          string `json:"app_id_env"`
	PrivateKey        string `json:"app_private_key"`
	PrivateKeyEnv     string `json:"app_private_key_env"`
	InstallationID    string `json:"app_installation_id"`
	InstallationIDEnv string `json:"app_installation_id_env"`
}

type JobInput struct {
	Profile     string     `json:"profile"`
	Action      string     `json:"action"`
	Owner       string     `json:"owner"`
	Repo        string     `json:"repo"`
	Repository  string     `json:"repository"`
	IssueNumber int        `json:"issue_number"`
	PullNumber  int        `json:"pull_number"`
	Title       string     `json:"title"`
	Body        string     `json:"body"`
	Labels      []string   `json:"labels"`
	Assignees   []string   `json:"assignees"`
	Base        string     `json:"base"`
	Head        string     `json:"head"`
	State       string     `json:"state"`
	Query       string     `json:"query"`
	PerPage     int        `json:"per_page"`
	Page        int        `json:"page"`
	CommentBody string     `json:"comment_body"`
	Path        string     `json:"path"`
	Ref         string     `json:"ref"`
	Draft       bool       `json:"draft"`
	Auth        InlineAuth `json:"auth"`
}

type callResult struct {
	JobID      string            `json:"job_id"`
	Profile    string            `json:"profile"`
	Action     string            `json:"action"`
	Owner      string            `json:"owner"`
	Repo       string            `json:"repo"`
	StatusCode int               `json:"status_code"`
	RequestID  string            `json:"request_id,omitempty"`
	DurationMs int64             `json:"duration_ms"`
	RateLimit  map[string]string `json:"rate_limit,omitempty"`
	Result     any               `json:"result,omitempty"`
	Error      string            `json:"error,omitempty"`
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
		Capabilities:    []string{"github"},
		Labels:          map[string]string{"adapter": "github"},
		Type:            "github",
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

	intent, err := classifyAction(action)
	if err != nil {
		return w.failJob(jobID, err)
	}
	if err := w.enforceTopic(req.GetTopic(), intent); err != nil {
		return w.failJob(jobID, err)
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return w.failJob(jobID, err)
	}

	owner, repo, repoFull, err := resolveRepo(input)
	if err != nil {
		return w.failJob(jobID, err)
	}
	if err := enforceRepoPolicy(profile, repoFull); err != nil {
		return w.failJob(jobID, err)
	}
	if err := enforceActionPolicy(profile, action); err != nil {
		return w.failJob(jobID, err)
	}

	tokenProvider, tokenType, err := w.resolveAuth(profile, input.Auth)
	if err != nil {
		return w.failJob(jobID, err)
	}

	client := githubapi.NewClient(profile.BaseURL, tokenProvider, githubapi.Options{
		Headers:    profile.Headers,
		UserAgent:  profile.UserAgent,
		APIVersion: profile.APIVersion,
		TokenType:  tokenType,
		Timeout:    w.requestTimeout(profile),
	})

	callCtx, cancel := context.WithTimeout(ctx, w.requestTimeout(profile))
	defer cancel()

	start := time.Now()
	response, err := w.execute(callCtx, client, action, input, owner, repo, repoFull)

	result := callResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     action,
		Owner:      owner,
		Repo:       repo,
		DurationMs: time.Since(start).Milliseconds(),
	}
	if response != nil {
		result.StatusCode = response.StatusCode
		result.RequestID = response.RequestID
		result.RateLimit = response.RateLimit
		result.Result = response.Body
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

func (w *Worker) resolveAuth(profile config.Profile, inline InlineAuth) (githubapi.TokenProvider, string, error) {
	inlineProvided := inline.HasAny()
	if inlineProvided && !w.cfg.AllowInlineAuth {
		return nil, "", fmt.Errorf("inline auth disabled")
	}

	token := resolveSecret(profile.Token, profile.TokenEnv)
	tokenType := strings.TrimSpace(profile.TokenType)
	if tokenType == "" {
		tokenType = "Bearer"
	}
	appID := resolveSecret(profile.App.AppID, profile.App.AppIDEnv)
	privateKey := resolveSecret(profile.App.PrivateKey, profile.App.PrivateKeyEnv)
	installationID := resolveSecret(profile.App.InstallationID, profile.App.InstallationIDEnv)

	if inlineProvided {
		if inline.Token != "" || inline.TokenEnv != "" {
			token = resolveSecret(inline.Token, inline.TokenEnv)
			tokenType = "Bearer"
		}
		if inline.AppID != "" || inline.AppIDEnv != "" {
			appID = resolveSecret(inline.AppID, inline.AppIDEnv)
		}
		if inline.PrivateKey != "" || inline.PrivateKeyEnv != "" {
			privateKey = resolveSecret(inline.PrivateKey, inline.PrivateKeyEnv)
		}
		if inline.InstallationID != "" || inline.InstallationIDEnv != "" {
			installationID = resolveSecret(inline.InstallationID, inline.InstallationIDEnv)
		}
	}

	if token != "" {
		return githubapi.StaticTokenProvider{TokenValue: token}, tokenType, nil
	}
	if appID != "" || privateKey != "" || installationID != "" {
		if appID == "" || privateKey == "" || installationID == "" {
			return nil, "", fmt.Errorf("github app auth requires app_id, private_key, and installation_id")
		}
		provider, err := githubapi.NewAppTokenProvider(profile.BaseURL, appID, installationID, privateKey, profile.UserAgent, profile.APIVersion, w.requestTimeout(profile))
		if err != nil {
			return nil, "", err
		}
		return provider, "Bearer", nil
	}
	return nil, "", fmt.Errorf("github auth required")
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
	if intent == "read" && topic != "job.github.read" {
		return fmt.Errorf("read actions must use job.github.read topic")
	}
	if intent == "write" && topic != "job.github.write" {
		return fmt.Errorf("write actions must use job.github.write topic")
	}
	return nil
}

func (w *Worker) execute(ctx context.Context, client *githubapi.Client, action string, input JobInput, owner, repo, repoFull string) (*githubapi.Response, error) {
	ownerEscaped := url.PathEscape(owner)
	repoEscaped := url.PathEscape(repo)

	switch action {
	case actionReposGet:
		resp, err := client.Do(ctx, httpMethodGet, fmt.Sprintf("/repos/%s/%s", ownerEscaped, repoEscaped), nil, nil)
		return &resp, err
	case actionIssuesGet:
		if input.IssueNumber < 1 {
			return nil, fmt.Errorf("issue_number required")
		}
		resp, err := client.Do(ctx, httpMethodGet, fmt.Sprintf("/repos/%s/%s/issues/%d", ownerEscaped, repoEscaped, input.IssueNumber), nil, nil)
		return &resp, err
	case actionIssuesList:
		query := url.Values{}
		if input.State != "" {
			query.Set("state", input.State)
		}
		if input.PerPage > 0 {
			query.Set("per_page", fmt.Sprintf("%d", input.PerPage))
		}
		if input.Page > 0 {
			query.Set("page", fmt.Sprintf("%d", input.Page))
		}
		resp, err := client.Do(ctx, httpMethodGet, fmt.Sprintf("/repos/%s/%s/issues", ownerEscaped, repoEscaped), query, nil)
		return &resp, err
	case actionIssuesCreate:
		if strings.TrimSpace(input.Title) == "" {
			return nil, fmt.Errorf("title required")
		}
		payload := map[string]any{
			"title": input.Title,
		}
		if strings.TrimSpace(input.Body) != "" {
			payload["body"] = input.Body
		}
		if len(input.Labels) > 0 {
			payload["labels"] = input.Labels
		}
		if len(input.Assignees) > 0 {
			payload["assignees"] = input.Assignees
		}
		resp, err := client.Do(ctx, httpMethodPost, fmt.Sprintf("/repos/%s/%s/issues", ownerEscaped, repoEscaped), nil, payload)
		return &resp, err
	case actionIssuesComment:
		if input.IssueNumber < 1 {
			return nil, fmt.Errorf("issue_number required")
		}
		if strings.TrimSpace(input.CommentBody) == "" {
			return nil, fmt.Errorf("comment_body required")
		}
		payload := map[string]any{"body": input.CommentBody}
		resp, err := client.Do(ctx, httpMethodPost, fmt.Sprintf("/repos/%s/%s/issues/%d/comments", ownerEscaped, repoEscaped, input.IssueNumber), nil, payload)
		return &resp, err
	case actionPullsGet:
		if input.PullNumber < 1 {
			return nil, fmt.Errorf("pull_number required")
		}
		resp, err := client.Do(ctx, httpMethodGet, fmt.Sprintf("/repos/%s/%s/pulls/%d", ownerEscaped, repoEscaped, input.PullNumber), nil, nil)
		return &resp, err
	case actionPullsCreate:
		if strings.TrimSpace(input.Title) == "" {
			return nil, fmt.Errorf("title required")
		}
		if strings.TrimSpace(input.Head) == "" {
			return nil, fmt.Errorf("head required")
		}
		if strings.TrimSpace(input.Base) == "" {
			return nil, fmt.Errorf("base required")
		}
		payload := map[string]any{
			"title": input.Title,
			"head":  input.Head,
			"base":  input.Base,
			"draft": input.Draft,
		}
		if strings.TrimSpace(input.Body) != "" {
			payload["body"] = input.Body
		}
		resp, err := client.Do(ctx, httpMethodPost, fmt.Sprintf("/repos/%s/%s/pulls", ownerEscaped, repoEscaped), nil, payload)
		return &resp, err
	case actionSearchIssues:
		queryString := strings.TrimSpace(input.Query)
		if queryString == "" {
			return nil, fmt.Errorf("query required")
		}
		repoQualifier := fmt.Sprintf("repo:%s", repoFull)
		if !strings.Contains(queryString, "repo:") {
			queryString = repoQualifier + " " + queryString
		}
		query := url.Values{}
		query.Set("q", queryString)
		if input.PerPage > 0 {
			query.Set("per_page", fmt.Sprintf("%d", input.PerPage))
		}
		if input.Page > 0 {
			query.Set("page", fmt.Sprintf("%d", input.Page))
		}
		resp, err := client.Do(ctx, httpMethodGet, "/search/issues", query, nil)
		return &resp, err
	case actionContentsGet:
		if strings.TrimSpace(input.Path) == "" {
			return nil, fmt.Errorf("path required")
		}
		escapedPath := escapePath(input.Path)
		query := url.Values{}
		if strings.TrimSpace(input.Ref) != "" {
			query.Set("ref", input.Ref)
		}
		resp, err := client.Do(ctx, httpMethodGet, fmt.Sprintf("/repos/%s/%s/contents/%s", ownerEscaped, repoEscaped, escapedPath), query, nil)
		return &resp, err
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
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

func classifyAction(action string) (string, error) {
	switch action {
	case actionReposGet, actionIssuesGet, actionIssuesList, actionPullsGet, actionSearchIssues, actionContentsGet:
		return "read", nil
	case actionIssuesCreate, actionIssuesComment, actionPullsCreate:
		return "write", nil
	default:
		return "", fmt.Errorf("unsupported action: %s", action)
	}
}

func enforceRepoPolicy(profile config.Profile, repo string) error {
	if len(profile.AllowedRepos) > 0 && !matchAny(profile.AllowedRepos, repo) {
		return fmt.Errorf("repository not allowed: %s", repo)
	}
	if matchAny(profile.DeniedRepos, repo) {
		return fmt.Errorf("repository denied: %s", repo)
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

func resolveRepo(input JobInput) (string, string, string, error) {
	owner := strings.TrimSpace(input.Owner)
	repo := strings.TrimSpace(input.Repo)
	if owner == "" || repo == "" {
		repository := strings.TrimSpace(input.Repository)
		if repository != "" {
			parts := strings.SplitN(repository, "/", 2)
			if len(parts) == 2 {
				owner = strings.TrimSpace(parts[0])
				repo = strings.TrimSpace(parts[1])
			}
		}
	}
	if owner == "" || repo == "" {
		return "", "", "", fmt.Errorf("repository required")
	}
	repoFull := owner + "/" + repo
	return owner, repo, repoFull, nil
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

func escapePath(raw string) string {
	trimmed := strings.Trim(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
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
		strings.TrimSpace(a.AppID) != "" ||
		strings.TrimSpace(a.AppIDEnv) != "" ||
		strings.TrimSpace(a.PrivateKey) != "" ||
		strings.TrimSpace(a.PrivateKeyEnv) != "" ||
		strings.TrimSpace(a.InstallationID) != "" ||
		strings.TrimSpace(a.InstallationIDEnv) != ""
}

const (
	httpMethodGet  = "GET"
	httpMethodPost = "POST"
)
