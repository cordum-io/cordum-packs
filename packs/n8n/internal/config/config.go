package config

import (
	"encoding/json"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL     = "http://localhost:8081"
	defaultNatsURL        = "nats://localhost:4222"
	defaultRedisURL       = "redis://localhost:6379"
	defaultPool           = "n8n"
	defaultQueue          = "n8n"
	defaultSubject        = "job.n8n.*"
	defaultRequestTimeout = 120 * time.Second
	defaultBaseURL        = "http://localhost:5678"
	defaultWebhookListen  = ":9100"
	defaultExecutePoll    = 2 * time.Second
	defaultExecuteWait    = 5 * time.Minute
)

// Profile holds per-profile n8n configuration.
type Profile struct {
	Name             string   `json:"name"`
	BaseURL          string   `json:"base_url"`
	APIKey           string   `json:"api_key"`
	APIKeyEnv        string   `json:"api_key_env"`
	AllowedWorkflows []string `json:"allowed_workflows"`
	DeniedWorkflows  []string `json:"denied_workflows"`
}

// Config holds all n8n pack configuration.
type Config struct {
	GatewayURL     string
	APIKey         string
	TenantID       string
	NatsURL        string
	RedisURL       string
	Pool           string
	Queue          string
	Subjects       []string
	MaxParallel    int32
	RequestTimeout time.Duration
	ResultTTL      time.Duration

	BaseURL             string
	N8nAPIKey           string
	DefaultProfile      string
	Profiles            map[string]Profile
	WebhookEnabled      bool
	WebhookListen       string
	WebhookSecret       string
	WebhookWorkflowMap  map[string]string
	AllowedWorkflows    []string
	DeniedWorkflows     []string
	ExecutePollInterval time.Duration
	ExecuteWaitTimeout  time.Duration
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:          envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:              strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:            envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:             envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:            envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:                envOr("CORDUM_N8N_POOL", defaultPool),
		Queue:               envOr("CORDUM_N8N_QUEUE", defaultQueue),
		RequestTimeout:      parseDuration("CORDUM_N8N_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:           parseDuration("CORDUM_N8N_RESULT_TTL", 0),
		BaseURL:             envOr("N8N_API_URL", envOr("CORDUM_N8N_BASE_URL", defaultBaseURL)),
		N8nAPIKey:           envOr("N8N_API_KEY", strings.TrimSpace(os.Getenv("CORDUM_N8N_API_KEY"))),
		DefaultProfile:      strings.TrimSpace(os.Getenv("CORDUM_N8N_DEFAULT_PROFILE")),
		Profiles:            map[string]Profile{},
		WebhookEnabled:      boolEnv("CORDUM_N8N_WEBHOOK_ENABLED", false),
		WebhookListen:       envOr("CORDUM_N8N_WEBHOOK_LISTEN", defaultWebhookListen),
		WebhookSecret:       strings.TrimSpace(os.Getenv("CORDUM_N8N_WEBHOOK_SECRET")),
		WebhookWorkflowMap:  map[string]string{},
		AllowedWorkflows:    splitList(os.Getenv("CORDUM_N8N_ALLOWED_WORKFLOWS")),
		DeniedWorkflows:     splitList(os.Getenv("CORDUM_N8N_DENIED_WORKFLOWS")),
		ExecutePollInterval: parseDuration("CORDUM_N8N_EXECUTION_POLL_INTERVAL", defaultExecutePoll),
		ExecuteWaitTimeout:  parseDuration("CORDUM_N8N_EXECUTION_WAIT_TIMEOUT", defaultExecuteWait),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_N8N_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_N8N_MAX_PARALLEL")); raw != "" {
		if value, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(value)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_N8N_WEBHOOK_WORKFLOW_MAP")); raw != "" {
		var mapping map[string]string
		if err := json.Unmarshal([]byte(raw), &mapping); err != nil {
			return cfg, err
		}
		for key, value := range mapping {
			cfg.WebhookWorkflowMap[normalizeWebhookPath(key)] = strings.TrimSpace(value)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_N8N_PROFILES")); raw != "" {
		var profiles []Profile
		if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
			return cfg, err
		}
		for _, profile := range profiles {
			profile = normalizeProfile(profile, cfg)
			if strings.TrimSpace(profile.Name) == "" {
				continue
			}
			cfg.Profiles[profile.Name] = profile
		}
	}
	if len(cfg.Profiles) == 0 {
		defaultProfile := normalizeProfile(Profile{
			Name:             "default",
			BaseURL:          cfg.BaseURL,
			APIKey:           cfg.N8nAPIKey,
			AllowedWorkflows: cfg.AllowedWorkflows,
			DeniedWorkflows:  cfg.DeniedWorkflows,
		}, cfg)
		cfg.Profiles[defaultProfile.Name] = defaultProfile
	}
	if cfg.DefaultProfile == "" {
		if _, ok := cfg.Profiles["default"]; ok {
			cfg.DefaultProfile = "default"
		} else {
			for name := range cfg.Profiles {
				cfg.DefaultProfile = name
				break
			}
		}
	}
	if cfg.ExecutePollInterval <= 0 {
		cfg.ExecutePollInterval = defaultExecutePoll
	}
	if cfg.ExecuteWaitTimeout <= 0 {
		cfg.ExecuteWaitTimeout = defaultExecuteWait
	}
	return cfg, nil
}

// ResolveProfile returns the named profile or the default profile.
func (c Config) ResolveProfile(name string) Profile {
	if trimmed := strings.TrimSpace(name); trimmed != "" {
		if profile, ok := c.Profiles[trimmed]; ok {
			return profile
		}
	}
	if profile, ok := c.Profiles[c.DefaultProfile]; ok {
		return profile
	}
	return normalizeProfile(Profile{Name: "default"}, c)
}

// ResolveAPIKey returns the resolved API key for the profile.
func (p Profile) ResolveAPIKey() string {
	if strings.TrimSpace(p.APIKeyEnv) != "" {
		if value := strings.TrimSpace(os.Getenv(p.APIKeyEnv)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(p.APIKey)
}

// IsWorkflowAllowed checks workflow allow/deny rules.
func (p Profile) IsWorkflowAllowed(workflow string) bool {
	workflow = strings.TrimSpace(workflow)
	if workflow == "" {
		return false
	}
	for _, denied := range p.DeniedWorkflows {
		if matchGlob(denied, workflow) {
			return false
		}
	}
	if len(p.AllowedWorkflows) == 0 {
		return true
	}
	for _, allowed := range p.AllowedWorkflows {
		if matchGlob(allowed, workflow) {
			return true
		}
	}
	return false
}

func normalizeProfile(profile Profile, cfg Config) Profile {
	if strings.TrimSpace(profile.BaseURL) == "" {
		profile.BaseURL = cfg.BaseURL
	}
	if strings.TrimSpace(profile.APIKey) == "" {
		profile.APIKey = cfg.N8nAPIKey
	}
	if len(profile.AllowedWorkflows) == 0 {
		profile.AllowedWorkflows = append([]string(nil), cfg.AllowedWorkflows...)
	}
	if len(profile.DeniedWorkflows) == 0 {
		profile.DeniedWorkflows = append([]string(nil), cfg.DeniedWorkflows...)
	}
	return profile
}

func normalizeWebhookPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return value
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func parseDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func splitList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		candidate := strings.TrimSpace(part)
		if candidate != "" {
			out = append(out, candidate)
		}
	}
	return out
}

func matchGlob(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" {
		return false
	}
	if pattern == value {
		return true
	}
	ok, err := path.Match(pattern, value)
	if err == nil && ok {
		return true
	}
	if pattern == "*" {
		return true
	}
	return false
}
