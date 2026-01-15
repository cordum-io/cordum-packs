package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/mcp-client/internal/config"
	"github.com/cordum-io/cordum-packs/packs/mcp-client/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/mcp-client/internal/mcpclient"
)

const (
	defaultAuthHeader = "X-API-Key"
)

type Worker struct {
	cfg     config.Config
	gateway *gatewayclient.Client
	redis   *redis.Client
	worker  *runtime.Worker
}

type JobInput struct {
	Server          string            `json:"server"`
	Transport       string            `json:"transport,omitempty"`
	Command         string            `json:"command,omitempty"`
	Args            []string          `json:"args,omitempty"`
	URL             string            `json:"url,omitempty"`
	Method          string            `json:"method,omitempty"`
	Tool            string            `json:"tool,omitempty"`
	Arguments       map[string]any    `json:"arguments,omitempty"`
	URI             string            `json:"uri,omitempty"`
	Params          map[string]any    `json:"params,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Env             map[string]string `json:"env,omitempty"`
	Auth            config.AuthConfig `json:"auth,omitempty"`
	TimeoutSeconds  int               `json:"timeout_seconds,omitempty"`
	ProtocolVersion string            `json:"protocol_version,omitempty"`
}

type callResult struct {
	JobID      string `json:"job_id"`
	Server     string `json:"server"`
	Transport  string `json:"transport"`
	Method     string `json:"method"`
	RequestID  any    `json:"request_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
	ServerInfo any    `json:"server_info,omitempty"`
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
		Capabilities:    []string{"mcp-client"},
		Labels:          map[string]string{"adapter": "mcp-client"},
		Type:            "mcp-client",
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
	server, err := w.resolveServer(input)
	if err != nil {
		return w.failJob(jobID, err)
	}
	method, params, err := resolveMethodParams(input, server)
	if err != nil {
		return w.failJob(jobID, err)
	}
	timeout := w.cfg.CallTimeout
	if input.TimeoutSeconds > 0 {
		timeout = time.Duration(input.TimeoutSeconds) * time.Second
	} else if server.TimeoutSeconds > 0 {
		timeout = time.Duration(server.TimeoutSeconds) * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := w.execute(callCtx, input, server, method, params)
	if err != nil {
		result.Error = err.Error()
		return w.finishJob(jobID, result, err)
	}
	return w.finishJob(jobID, result, nil)
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

func (w *Worker) resolveServer(input JobInput) (config.ServerConfig, error) {
	inlineAllowed := w.cfg.AllowInlineServer
	var base config.ServerConfig
	if strings.TrimSpace(input.Server) != "" {
		server, ok := w.cfg.Servers[input.Server]
		if !ok {
			return config.ServerConfig{}, fmt.Errorf("unknown server: %s", input.Server)
		}
		if !inlineAllowed && hasInlineServerOverrides(input) {
			return config.ServerConfig{}, fmt.Errorf("inline server config disabled")
		}
		base = server
		base.Name = input.Server
	} else if !inlineAllowed {
		return config.ServerConfig{}, fmt.Errorf("inline server config disabled")
	}

	server := base
	if inlineAllowed {
		if strings.TrimSpace(input.Transport) != "" {
			server.Transport = input.Transport
		}
		if strings.TrimSpace(input.Command) != "" {
			server.Command = input.Command
		}
		if strings.TrimSpace(input.URL) != "" {
			server.URL = input.URL
		}
		if len(input.Args) > 0 {
			server.Args = append([]string{}, input.Args...)
		}
		server.Env = mergeStringMap(server.Env, input.Env)
		server.Headers = mergeStringMap(server.Headers, input.Headers)
	}
	server.Auth = mergeAuth(server.Auth, input.Auth)
	if input.TimeoutSeconds > 0 {
		server.TimeoutSeconds = input.TimeoutSeconds
	}
	if strings.TrimSpace(input.ProtocolVersion) != "" {
		server.ProtocolVersion = input.ProtocolVersion
	}
	if server.Transport == "" {
		switch {
		case server.URL != "":
			server.Transport = "http"
		case server.Command != "":
			server.Transport = "stdio"
		}
	}
	if strings.TrimSpace(server.ProtocolVersion) == "" {
		server.ProtocolVersion = w.cfg.ProtocolVersion
	}
	switch strings.ToLower(strings.TrimSpace(server.Transport)) {
	case "stdio":
		if strings.TrimSpace(server.Command) == "" {
			return config.ServerConfig{}, fmt.Errorf("stdio command required")
		}
	case "http":
		if strings.TrimSpace(server.URL) == "" {
			return config.ServerConfig{}, fmt.Errorf("http url required")
		}
		if _, err := url.ParseRequestURI(server.URL); err != nil {
			return config.ServerConfig{}, fmt.Errorf("invalid url: %w", err)
		}
	default:
		return config.ServerConfig{}, fmt.Errorf("unsupported transport: %s", server.Transport)
	}
	return server, nil
}

func hasInlineServerOverrides(input JobInput) bool {
	if strings.TrimSpace(input.Transport) != "" {
		return true
	}
	if strings.TrimSpace(input.Command) != "" {
		return true
	}
	if strings.TrimSpace(input.URL) != "" {
		return true
	}
	if len(input.Args) > 0 {
		return true
	}
	if len(input.Env) > 0 {
		return true
	}
	if len(input.Headers) > 0 {
		return true
	}
	return false
}

func resolveMethodParams(input JobInput, server config.ServerConfig) (string, map[string]any, error) {
	method := strings.TrimSpace(input.Method)
	if method == "" {
		if strings.TrimSpace(input.Tool) != "" {
			method = "tools/call"
		} else {
			return "", nil, fmt.Errorf("method required")
		}
	}
	if !isAllowedMethod(method) {
		return "", nil, fmt.Errorf("unsupported method: %s", method)
	}
	params := input.Params
	if params == nil {
		switch method {
		case "tools/call":
			if strings.TrimSpace(input.Tool) == "" {
				return "", nil, fmt.Errorf("tool name required")
			}
			if !toolAllowed(input.Tool, server.AllowTools, server.DenyTools) {
				return "", nil, fmt.Errorf("tool not allowed: %s", input.Tool)
			}
			params = map[string]any{
				"name":      input.Tool,
				"arguments": input.Arguments,
			}
		case "resources/read":
			if strings.TrimSpace(input.URI) == "" {
				return "", nil, fmt.Errorf("uri required")
			}
			params = map[string]any{
				"uri": input.URI,
			}
		default:
			params = map[string]any{}
		}
	}
	return method, params, nil
}

func (w *Worker) execute(ctx context.Context, input JobInput, server config.ServerConfig, method string, params map[string]any) (callResult, error) {
	start := time.Now()
	serverName := server.Name
	if serverName == "" {
		serverName = strings.TrimSpace(input.Server)
	}
	transport := strings.ToLower(strings.TrimSpace(server.Transport))
	mcpServer := mcpclient.Server{
		Name:      serverName,
		Transport: transport,
		Command:   server.Command,
		Args:      server.Args,
		URL:       server.URL,
		Env:       mergeStringMap(server.Env, nil),
		Headers:   mergeStringMap(server.Headers, nil),
	}
	if err := applyAuth(ctx, &mcpServer, server.Auth); err != nil {
		return callResult{}, err
	}
	session, err := mcpclient.NewSession(ctx, mcpServer)
	if err != nil {
		return callResult{}, err
	}
	defer session.Close()
	initResult, err := session.Initialize(ctx, server.ProtocolVersion, mcpclient.ClientInfo{
		Name:    w.cfg.ClientName,
		Version: w.cfg.ClientVersion,
	})
	if err != nil {
		return callResult{}, err
	}
	resp, err := session.CallRaw(ctx, method, params)
	if err != nil {
		return callResult{}, err
	}
	if resp.Error != nil {
		return callResult{}, fmt.Errorf("%s", resp.Error.Message)
	}
	var out any
	if len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, &out); err != nil {
			return callResult{}, err
		}
	}
	result := callResult{
		JobID:      "",
		Server:     serverName,
		Transport:  transport,
		Method:     method,
		RequestID:  resp.ID,
		DurationMs: time.Since(start).Milliseconds(),
		Result:     out,
	}
	if info, ok := initResult["serverInfo"]; ok {
		result.ServerInfo = info
	}
	return result, nil
}

func (w *Worker) finishJob(jobID string, result callResult, err error) (*agentv1.JobResult, error) {
	result.JobID = jobID
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
	if err := w.redis.Set(ctx, key, data, 0).Err(); err != nil {
		return "", err
	}
	return "redis://" + key, nil
}

func mergeStringMap(base, overlay map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		if strings.TrimSpace(key) == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func mergeAuth(base, overlay config.AuthConfig) config.AuthConfig {
	out := base
	if overlay.APIKey != "" {
		out.APIKey = overlay.APIKey
	}
	if overlay.APIKeyEnv != "" {
		out.APIKeyEnv = overlay.APIKeyEnv
	}
	if overlay.APIKeyHeader != "" {
		out.APIKeyHeader = overlay.APIKeyHeader
	}
	if overlay.Bearer != "" {
		out.Bearer = overlay.Bearer
	}
	if overlay.BearerEnv != "" {
		out.BearerEnv = overlay.BearerEnv
	}
	if overlay.BasicUsername != "" {
		out.BasicUsername = overlay.BasicUsername
	}
	if overlay.BasicPassword != "" {
		out.BasicPassword = overlay.BasicPassword
	}
	if overlay.BasicPasswordEnv != "" {
		out.BasicPasswordEnv = overlay.BasicPasswordEnv
	}
	if overlay.OAuth != nil {
		if out.OAuth == nil {
			out.OAuth = &config.OAuthConfig{}
		}
		mergeOAuth(out.OAuth, overlay.OAuth)
	}
	return out
}

func mergeOAuth(base, overlay *config.OAuthConfig) {
	if overlay == nil {
		return
	}
	if overlay.TokenURL != "" {
		base.TokenURL = overlay.TokenURL
	}
	if overlay.ClientID != "" {
		base.ClientID = overlay.ClientID
	}
	if overlay.ClientSecret != "" {
		base.ClientSecret = overlay.ClientSecret
	}
	if overlay.ClientSecretEnv != "" {
		base.ClientSecretEnv = overlay.ClientSecretEnv
	}
	if len(overlay.Scopes) > 0 {
		base.Scopes = append([]string{}, overlay.Scopes...)
	}
	if overlay.Audience != "" {
		base.Audience = overlay.Audience
	}
}

func toolAllowed(tool string, allow, deny []string) bool {
	for _, entry := range deny {
		if strings.EqualFold(strings.TrimSpace(entry), tool) {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, entry := range allow {
		if strings.EqualFold(strings.TrimSpace(entry), tool) {
			return true
		}
	}
	return false
}

func isAllowedMethod(method string) bool {
	switch method {
	case "tools/call", "tools/list", "resources/list", "resources/templates/list", "resources/read", "ping":
		return true
	default:
		return false
	}
}

func validateInlineAuth(auth config.AuthConfig, allow bool) error {
	if allow {
		return nil
	}
	if auth.APIKey != "" || auth.Bearer != "" || auth.BasicPassword != "" {
		return fmt.Errorf("inline auth secrets are disabled")
	}
	if auth.OAuth != nil && auth.OAuth.ClientSecret != "" {
		return fmt.Errorf("inline oauth client_secret is disabled")
	}
	return nil
}

func applyAuth(ctx context.Context, server *mcpclient.Server, auth config.AuthConfig) error {
	apiKey := resolveSecret(auth.APIKey, auth.APIKeyEnv)
	bearer := resolveSecret(auth.Bearer, auth.BearerEnv)
	basicPassword := resolveSecret(auth.BasicPassword, auth.BasicPasswordEnv)
	basicUser := strings.TrimSpace(auth.BasicUsername)
	if auth.OAuth != nil {
		token, err := fetchOAuthToken(ctx, auth.OAuth)
		if err != nil {
			return err
		}
		if token != "" {
			bearer = token
		}
	}
	if bearer != "" && basicPassword != "" {
		return fmt.Errorf("cannot combine bearer and basic auth")
	}
	if apiKey != "" {
		header := defaultAuthHeader
		if strings.TrimSpace(auth.APIKeyHeader) != "" {
			header = strings.TrimSpace(auth.APIKeyHeader)
		}
		server.Headers = mergeStringMap(server.Headers, map[string]string{header: apiKey})
		server.Env = mergeStringMap(server.Env, map[string]string{"MCP_API_KEY": apiKey})
	}
	if bearer != "" {
		server.Headers = mergeStringMap(server.Headers, map[string]string{"Authorization": "Bearer " + bearer})
		server.Env = mergeStringMap(server.Env, map[string]string{"MCP_BEARER_TOKEN": bearer})
	}
	if basicPassword != "" || basicUser != "" {
		server.Headers = mergeStringMap(server.Headers, map[string]string{"Authorization": mcpclient.EncodeBasicAuth(basicUser, basicPassword)})
		server.Env = mergeStringMap(server.Env, map[string]string{"MCP_BASIC_USER": basicUser, "MCP_BASIC_PASSWORD": basicPassword})
	}
	return nil
}

func resolveSecret(value, envKey string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	if strings.TrimSpace(envKey) != "" {
		return strings.TrimSpace(os.Getenv(envKey))
	}
	return ""
}

type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func fetchOAuthToken(ctx context.Context, cfg *config.OAuthConfig) (string, error) {
	if cfg == nil {
		return "", nil
	}
	if strings.TrimSpace(cfg.TokenURL) == "" {
		return "", fmt.Errorf("oauth token_url required")
	}
	clientSecret := resolveSecret(cfg.ClientSecret, cfg.ClientSecretEnv)
	if strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return "", fmt.Errorf("oauth client credentials required")
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", clientSecret)
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if strings.TrimSpace(cfg.Audience) != "" {
		form.Set("audience", cfg.Audience)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("oauth token request failed: %s", resp.Status)
	}
	var payload oauthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return strings.TrimSpace(payload.AccessToken), nil
}
