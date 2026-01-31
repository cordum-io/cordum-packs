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
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/slack/internal/config"
	"github.com/cordum-io/cordum-packs/packs/slack/internal/slackapi"
)

const (
	httpMethodGet  = "GET"
	httpMethodPost = "POST"
)

type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
}

type InlineAuth struct {
	Token    string `json:"token"`
	TokenEnv string `json:"token_env"`
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
	ChannelKeys  []string
	Description  string
}

var actionSpecs = map[string]actionSpec{
	"auth.test":                        {Name: "auth.test", Method: httpMethodPost, Path: "/auth.test", Intent: "read", ParamsStyle: "json"},
	"conversations.list":               {Name: "conversations.list", Method: httpMethodGet, Path: "/conversations.list", Intent: "read", ParamsStyle: "query"},
	"conversations.info":               {Name: "conversations.info", Method: httpMethodGet, Path: "/conversations.info", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"conversations.history":            {Name: "conversations.history", Method: httpMethodGet, Path: "/conversations.history", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"conversations.replies":            {Name: "conversations.replies", Method: httpMethodGet, Path: "/conversations.replies", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"conversations.members":            {Name: "conversations.members", Method: httpMethodGet, Path: "/conversations.members", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"conversations.listconnectedteams": {Name: "conversations.listConnectedTeams", Method: httpMethodGet, Path: "/conversations.listConnectedTeams", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"users.list":                       {Name: "users.list", Method: httpMethodGet, Path: "/users.list", Intent: "read", ParamsStyle: "query"},
	"users.info":                       {Name: "users.info", Method: httpMethodGet, Path: "/users.info", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"user"}},
	"team.info":                        {Name: "team.info", Method: httpMethodGet, Path: "/team.info", Intent: "read", ParamsStyle: "query"},
	"chat.getpermalink":                {Name: "chat.getPermalink", Method: httpMethodGet, Path: "/chat.getPermalink", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"channel", "message_ts"}, ChannelKeys: []string{"channel"}},
	"search.messages":                  {Name: "search.messages", Method: httpMethodGet, Path: "/search.messages", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"query"}},
	"pins.list":                        {Name: "pins.list", Method: httpMethodGet, Path: "/pins.list", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"files.list":                       {Name: "files.list", Method: httpMethodGet, Path: "/files.list", Intent: "read", ParamsStyle: "query"},
	"files.info":                       {Name: "files.info", Method: httpMethodGet, Path: "/files.info", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"file"}},
	"usergroups.list":                  {Name: "usergroups.list", Method: httpMethodGet, Path: "/usergroups.list", Intent: "read", ParamsStyle: "query"},
	"bookmarks.list":                   {Name: "bookmarks.list", Method: httpMethodGet, Path: "/bookmarks.list", Intent: "read", ParamsStyle: "query", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"chat.postmessage":                 {Name: "chat.postMessage", Method: httpMethodPost, Path: "/chat.postMessage", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"chat.update":                      {Name: "chat.update", Method: httpMethodPost, Path: "/chat.update", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "ts"}, ChannelKeys: []string{"channel"}},
	"chat.delete":                      {Name: "chat.delete", Method: httpMethodPost, Path: "/chat.delete", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "ts"}, ChannelKeys: []string{"channel"}},
	"chat.postephemeral":               {Name: "chat.postEphemeral", Method: httpMethodPost, Path: "/chat.postEphemeral", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "user"}, ChannelKeys: []string{"channel"}},
	"chat.schedulemessage":             {Name: "chat.scheduleMessage", Method: httpMethodPost, Path: "/chat.scheduleMessage", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "post_at", "text"}, ChannelKeys: []string{"channel"}},
	"chat.deletescheduledmessage":      {Name: "chat.deleteScheduledMessage", Method: httpMethodPost, Path: "/chat.deleteScheduledMessage", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "scheduled_message_id"}, ChannelKeys: []string{"channel"}},
	"reactions.add":                    {Name: "reactions.add", Method: httpMethodPost, Path: "/reactions.add", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "name", "timestamp"}, ChannelKeys: []string{"channel"}},
	"reactions.remove":                 {Name: "reactions.remove", Method: httpMethodPost, Path: "/reactions.remove", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "name", "timestamp"}, ChannelKeys: []string{"channel"}},
	"conversations.create":             {Name: "conversations.create", Method: httpMethodPost, Path: "/conversations.create", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"name"}},
	"conversations.rename":             {Name: "conversations.rename", Method: httpMethodPost, Path: "/conversations.rename", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "name"}, ChannelKeys: []string{"channel"}},
	"conversations.invite":             {Name: "conversations.invite", Method: httpMethodPost, Path: "/conversations.invite", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "users"}, ChannelKeys: []string{"channel"}},
	"conversations.kick":               {Name: "conversations.kick", Method: httpMethodPost, Path: "/conversations.kick", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "user"}, ChannelKeys: []string{"channel"}},
	"conversations.setpurpose":         {Name: "conversations.setPurpose", Method: httpMethodPost, Path: "/conversations.setPurpose", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "purpose"}, ChannelKeys: []string{"channel"}},
	"conversations.settopic":           {Name: "conversations.setTopic", Method: httpMethodPost, Path: "/conversations.setTopic", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "topic"}, ChannelKeys: []string{"channel"}},
	"conversations.archive":            {Name: "conversations.archive", Method: httpMethodPost, Path: "/conversations.archive", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"conversations.unarchive":          {Name: "conversations.unarchive", Method: httpMethodPost, Path: "/conversations.unarchive", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"conversations.leave":              {Name: "conversations.leave", Method: httpMethodPost, Path: "/conversations.leave", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"pins.add":                         {Name: "pins.add", Method: httpMethodPost, Path: "/pins.add", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"pins.remove":                      {Name: "pins.remove", Method: httpMethodPost, Path: "/pins.remove", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel"}, ChannelKeys: []string{"channel"}},
	"usergroups.create":                {Name: "usergroups.create", Method: httpMethodPost, Path: "/usergroups.create", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"name"}},
	"usergroups.update":                {Name: "usergroups.update", Method: httpMethodPost, Path: "/usergroups.update", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"usergroup"}},
	"usergroups.users.update":          {Name: "usergroups.users.update", Method: httpMethodPost, Path: "/usergroups.users.update", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"usergroup", "users"}},
	"bookmarks.add":                    {Name: "bookmarks.add", Method: httpMethodPost, Path: "/bookmarks.add", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "title"}, ChannelKeys: []string{"channel"}},
	"bookmarks.edit":                   {Name: "bookmarks.edit", Method: httpMethodPost, Path: "/bookmarks.edit", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "bookmark_id"}, ChannelKeys: []string{"channel"}},
	"bookmarks.remove":                 {Name: "bookmarks.remove", Method: httpMethodPost, Path: "/bookmarks.remove", Intent: "write", ParamsStyle: "json", RequiredKeys: []string{"channel", "bookmark_id"}, ChannelKeys: []string{"channel"}},
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "slack")
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
		subjects = []string{"job.slack.*"}
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

	action := strings.TrimSpace(input.Action)
	if action == "" {
		return callResult{}, fmt.Errorf("action required")
	}

	spec, ok := actionSpecs[strings.ToLower(action)]
	if !ok {
		return callResult{}, fmt.Errorf("unsupported action: %s", action)
	}
	if err := w.enforceTopic(ctx.Job.GetTopic(), spec.Intent); err != nil {
		return callResult{}, err
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}
	if err := validateParams(params, spec.RequiredKeys); err != nil {
		return callResult{}, err
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return callResult{}, err
	}
	if err := enforceActionPolicy(profile, spec.Name); err != nil {
		return callResult{}, err
	}

	channels := extractChannels(params, spec.ChannelKeys)
	if err := enforceChannelPolicy(profile, channels); err != nil {
		return callResult{}, err
	}

	tokenProvider, err := w.resolveAuth(profile, input.Auth)
	if err != nil {
		return callResult{}, err
	}

	client := slackapi.NewClient(profile.BaseURL, tokenProvider, slackapi.Options{
		Headers:   profile.Headers,
		UserAgent: profile.UserAgent,
		Timeout:   w.requestTimeout(profile),
	})

	callCtx, cancel := context.WithTimeout(context.Background(), w.requestTimeout(profile))
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
		if response.Error != "" {
			result.Error = response.Error
		}
	}
	if result.RequestID == "" && strings.TrimSpace(input.RequestID) != "" {
		result.RequestID = strings.TrimSpace(input.RequestID)
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result, err
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

func (w *Worker) resolveAuth(profile config.Profile, inline InlineAuth) (slackapi.TokenProvider, error) {
	inlineProvided := inline.HasAny()
	if inlineProvided && !w.cfg.AllowInlineAuth {
		return nil, fmt.Errorf("inline auth disabled")
	}

	token := resolveSecret(profile.Token, profile.TokenEnv)
	if inlineProvided {
		if inline.Token != "" || inline.TokenEnv != "" {
			token = resolveSecret(inline.Token, inline.TokenEnv)
		}
	}
	if token == "" {
		return nil, fmt.Errorf("slack token required")
	}
	return slackapi.StaticTokenProvider{TokenValue: token}, nil
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
		if topic != "job.slack.read" {
			return fmt.Errorf("read actions must use job.slack.read topic")
		}
	case "write":
		if topic != "job.slack.write" {
			return fmt.Errorf("write actions must use job.slack.write topic")
		}
	default:
		return fmt.Errorf("unknown action intent: %s", intent)
	}
	return nil
}

func (w *Worker) execute(ctx context.Context, client *slackapi.Client, spec actionSpec, params map[string]any) (*slackapi.Response, error) {
	var query url.Values
	var body any
	if spec.ParamsStyle == "query" {
		query = encodeQuery(params)
	} else {
		body = params
	}
	return client.Do(ctx, spec.Method, spec.Path, query, body)
}

func validateInlineAuth(auth InlineAuth, allowed, allowSecrets bool) error {
	if auth.HasAny() && !allowed {
		return fmt.Errorf("inline auth disabled")
	}
	if auth.HasSecrets() && !allowSecrets {
		return fmt.Errorf("inline secrets disabled; use token_env")
	}
	return nil
}

func validateParams(params map[string]any, required []string) error {
	for _, key := range required {
		if !hasParam(params, key) {
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

func extractChannels(params map[string]any, keys []string) []string {
	if len(keys) == 0 {
		keys = []string{"channel", "channel_id", "channels"}
	}
	seen := map[string]bool{}
	var channels []string
	for _, key := range keys {
		value, ok := params[key]
		if !ok {
			continue
		}
		for _, channel := range normalizeChannels(value) {
			if channel == "" || seen[channel] {
				continue
			}
			seen[channel] = true
			channels = append(channels, channel)
		}
	}
	return channels
}

func normalizeChannels(value any) []string {
	var channels []string
	switch val := value.(type) {
	case string:
		for _, part := range strings.Split(val, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				channels = append(channels, trimmed)
			}
		}
	case []string:
		for _, part := range val {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				channels = append(channels, trimmed)
			}
		}
	case []any:
		for _, item := range val {
			for _, channel := range normalizeChannels(item) {
				channels = append(channels, channel)
			}
		}
	}
	return channels
}

func enforceChannelPolicy(profile config.Profile, channels []string) error {
	if len(profile.AllowedChannels) == 0 && len(profile.DeniedChannels) == 0 {
		return nil
	}
	for _, channel := range channels {
		if channel == "" {
			continue
		}
		if len(profile.AllowedChannels) > 0 && !matchAny(profile.AllowedChannels, channel) {
			return fmt.Errorf("channel not allowed: %s", channel)
		}
		if matchAny(profile.DeniedChannels, channel) {
			return fmt.Errorf("channel denied: %s", channel)
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
	envKey = strings.TrimSpace(envKey)
	if envKey != "" {
		if envValue := strings.TrimSpace(os.Getenv(envKey)); envValue != "" {
			return envValue
		}
	}
	return strings.TrimSpace(value)
}

func (a InlineAuth) HasAny() bool {
	return strings.TrimSpace(a.Token) != "" || strings.TrimSpace(a.TokenEnv) != ""
}

func (a InlineAuth) HasSecrets() bool {
	return strings.TrimSpace(a.Token) != ""
}
