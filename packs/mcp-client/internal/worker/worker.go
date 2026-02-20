package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/mcp-client/internal/config"
	"github.com/cordum-io/cordum-packs/packs/mcp-client/internal/mcpclient"
)

const (
	defaultAuthHeader = "X-API-Key"
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
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "mcp-client")
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
		subjects = []string{"job.mcp-client.*"}
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

	result := callResult{
		JobID: jobID,
	}

	server, err := w.resolveServer(input)
	if err != nil {
		return callResult{}, err
	}
	method, params, err := resolveMethodParams(input, server)
	if err != nil {
		return callResult{}, err
	}
	timeout := w.cfg.CallTimeout
	if input.TimeoutSeconds > 0 {
		timeout = time.Duration(input.TimeoutSeconds) * time.Second
	} else if server.TimeoutSeconds > 0 {
		timeout = time.Duration(server.TimeoutSeconds) * time.Second
	}
	callCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err = w.execute(callCtx, input, server, method, params)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	return result, nil
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

func (w *Worker) resolveServer(input JobInput) (config.ServerConfig, error) {
	inlineAllowed := w.cfg.AllowInlineServer
	unsafeInlineAllowed := w.cfg.AllowInlineUnsafeServer
	if err := validateInlineAuth(input.Auth, w.cfg.AllowInlineAuth, w.cfg.AllowInlineSecrets); err != nil {
		return config.ServerConfig{}, err
	}
	var base config.ServerConfig
	if strings.TrimSpace(input.Server) != "" {
		server, ok := w.cfg.Servers[input.Server]
		if !ok {
			return config.ServerConfig{}, fmt.Errorf("unknown server: %s", input.Server)
		}
		if !inlineAllowed && hasInlineServerOverrides(input) {
			return config.ServerConfig{}, fmt.Errorf("inline server overrides disabled")
		}
		if inlineAllowed && !unsafeInlineAllowed && hasUnsafeInlineServerOverrides(input) {
			return config.ServerConfig{}, fmt.Errorf("inline server config disabled")
		}
		base = server
		base.Name = input.Server
	} else if !inlineAllowed {
		return config.ServerConfig{}, fmt.Errorf("inline server config disabled")
	} else if !unsafeInlineAllowed {
		return config.ServerConfig{}, fmt.Errorf("server required; inline server config disabled")
	}

	server := base
	if inlineAllowed && unsafeInlineAllowed {
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
	}
	if inlineAllowed {
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
		validatedURL, err := validateHTTPURL(server.URL)
		if err != nil {
			return config.ServerConfig{}, err
		}
		server.URL = validatedURL
	default:
		return config.ServerConfig{}, fmt.Errorf("unsupported transport: %s", server.Transport)
	}
	return server, nil
}

func hasInlineServerOverrides(input JobInput) bool {
	if hasUnsafeInlineServerOverrides(input) {
		return true
	}
	if len(input.Headers) > 0 {
		return true
	}
	return false
}

func hasUnsafeInlineServerOverrides(input JobInput) bool {
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
	if overlay.APICredential != "" {
		out.APICredential = overlay.APICredential
	}
	if overlay.APICredentialEnv != "" {
		out.APICredentialEnv = overlay.APICredentialEnv
	}
	if overlay.APICredentialHeader != "" {
		out.APICredentialHeader = overlay.APICredentialHeader
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

func validateInlineAuth(auth config.AuthConfig, allowInline, allowSecrets bool) error {
	if !allowInline && hasAuthValues(auth) {
		return fmt.Errorf("inline auth disabled")
	}
	if !allowSecrets && hasAuthSecrets(auth) {
		return fmt.Errorf("inline secrets disabled; use *_env fields")
	}
	return nil
}

func hasAuthValues(auth config.AuthConfig) bool {
	if strings.TrimSpace(auth.APICredential) != "" ||
		strings.TrimSpace(auth.APICredentialEnv) != "" ||
		strings.TrimSpace(auth.APICredentialHeader) != "" ||
		strings.TrimSpace(auth.Bearer) != "" ||
		strings.TrimSpace(auth.BearerEnv) != "" ||
		strings.TrimSpace(auth.BasicUsername) != "" ||
		strings.TrimSpace(auth.BasicPassword) != "" ||
		strings.TrimSpace(auth.BasicPasswordEnv) != "" {
		return true
	}
	if auth.OAuth == nil {
		return false
	}
	return strings.TrimSpace(auth.OAuth.TokenURL) != "" ||
		strings.TrimSpace(auth.OAuth.ClientID) != "" ||
		strings.TrimSpace(auth.OAuth.ClientCredential) != "" ||
		strings.TrimSpace(auth.OAuth.ClientCredentialEnv) != "" ||
		len(auth.OAuth.Scopes) > 0 ||
		strings.TrimSpace(auth.OAuth.Audience) != ""
}

func hasAuthSecrets(auth config.AuthConfig) bool {
	if strings.TrimSpace(auth.APICredential) != "" ||
		strings.TrimSpace(auth.Bearer) != "" ||
		strings.TrimSpace(auth.BasicPassword) != "" {
		return true
	}
	if auth.OAuth == nil {
		return false
	}
	return strings.TrimSpace(auth.OAuth.ClientCredential) != ""
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
	if overlay.ClientCredential != "" {
		base.ClientCredential = overlay.ClientCredential
	}
	if overlay.ClientCredentialEnv != "" {
		base.ClientCredentialEnv = overlay.ClientCredentialEnv
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

func applyAuth(ctx context.Context, server *mcpclient.Server, auth config.AuthConfig) error {
	apiKey := resolveSecret(auth.APICredential, auth.APICredentialEnv)
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
		if strings.TrimSpace(auth.APICredentialHeader) != "" {
			header = strings.TrimSpace(auth.APICredentialHeader)
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
	envKey = strings.TrimSpace(envKey)
	if envKey != "" {
		if envValue := strings.TrimSpace(os.Getenv(envKey)); envValue != "" {
			return envValue
		}
	}
	return strings.TrimSpace(value)
}

func validateHTTPURL(raw string) (string, error) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	if target == nil || target.Host == "" {
		return "", fmt.Errorf("url must include host")
	}
	scheme := strings.ToLower(strings.TrimSpace(target.Scheme))
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("url scheme must be http or https")
	}
	if target.User != nil {
		return "", fmt.Errorf("url must not include credentials")
	}
	target.Scheme = scheme
	target.Fragment = ""
	target.RawFragment = ""
	return target.String(), nil
}

type oauthTokenResponse struct {
	AccessValue string `json:"access_token"` // #nosec G117 -- OAuth response payload field; value is received at runtime
	TokenType   string `json:"token_type"`
}

func fetchOAuthToken(ctx context.Context, cfg *config.OAuthConfig) (string, error) {
	if cfg == nil {
		return "", nil
	}
	if strings.TrimSpace(cfg.TokenURL) == "" {
		return "", fmt.Errorf("oauth token_url required")
	}
	tokenURL, err := validateHTTPURL(cfg.TokenURL)
	if err != nil {
		return "", fmt.Errorf("invalid oauth token_url: %w", err)
	}
	clientSecret := resolveSecret(cfg.ClientCredential, cfg.ClientCredentialEnv)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req) // #nosec G107 G704 -- tokenURL is validated by validateHTTPURL before request execution
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
	return strings.TrimSpace(payload.AccessValue), nil
}
