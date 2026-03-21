package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL     = "http://localhost:8081"
	defaultNatsURL        = "nats://localhost:4222"
	defaultRedisURL       = "redis://localhost:6379"
	defaultPool           = "anthropic"
	defaultQueue          = "anthropic"
	defaultSubject        = "job.anthropic.*"
	defaultBaseURL        = "https://api.anthropic.com"
	defaultAPIVersion     = "2023-06-01"
	defaultUserAgent      = "cordum-anthropic-worker/0.1.0"
	defaultRequestTimeout = 120 * time.Second
	defaultMaxTokensLimit = 128000
	defaultThinkingMax    = 65536
)

// Profile holds per-profile configuration for multi-tenant setups.
type Profile struct {
	Name              string   `json:"name"`
	BaseURL           string   `json:"base_url"`
	APIKey            string   `json:"api_key"`
	APIKeyEnv         string   `json:"api_key_env"`
	APIVersion        string   `json:"api_version"`
	AllowedModels     []string `json:"allowed_models"`
	DeniedModels      []string `json:"denied_models"`
	MaxTokensLimit    int      `json:"max_tokens_limit"`
	ThinkingEnabled   bool     `json:"thinking_enabled"`
	ThinkingMaxBudget int      `json:"thinking_max_budget"`
	UserAgent         string   `json:"user_agent"`
}

// Config holds all Anthropic pack configuration.
type Config struct {
	GatewayURL     string
	APIKey         string // #nosec G117 -- runtime-supplied credential field
	TenantID       string
	NatsURL        string
	RedisURL       string
	Pool           string
	Queue          string
	Subjects       []string
	MaxParallel    int32
	RequestTimeout time.Duration
	ResultTTL      time.Duration

	// Anthropic-specific
	BaseURL           string
	APIVersion        string
	AllowedModels     []string
	DeniedModels      []string
	MaxTokensLimit    int
	ToolGovernance    bool
	ThinkingEnabled   bool
	ThinkingMaxBudget int
	UserAgent         string

	// Inline auth
	AllowInlineAuth    bool
	AllowInlineSecrets bool

	// Profiles
	DefaultProfile string
	Profiles       map[string]Profile
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:         strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")),
		TenantID:       envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_ANTHROPIC_POOL", defaultPool),
		Queue:          envOr("CORDUM_ANTHROPIC_QUEUE", defaultQueue),
		RequestTimeout: defaultRequestTimeout,
		ResultTTL:      parseDuration("CORDUM_ANTHROPIC_RESULT_TTL", 0),

		BaseURL:           envOr("CORDUM_ANTHROPIC_BASE_URL", defaultBaseURL),
		APIVersion:        envOr("CORDUM_ANTHROPIC_API_VERSION", defaultAPIVersion),
		MaxTokensLimit:    intEnv("CORDUM_ANTHROPIC_MAX_TOKENS_LIMIT", defaultMaxTokensLimit),
		ToolGovernance:    boolEnv("CORDUM_ANTHROPIC_TOOL_GOVERNANCE", true),
		ThinkingEnabled:   boolEnv("CORDUM_ANTHROPIC_THINKING_ENABLED", false),
		ThinkingMaxBudget: intEnv("CORDUM_ANTHROPIC_THINKING_MAX_BUDGET", defaultThinkingMax),
		UserAgent:         envOr("CORDUM_ANTHROPIC_USER_AGENT", defaultUserAgent),

		AllowInlineAuth:    boolEnv("CORDUM_ANTHROPIC_ALLOW_INLINE_AUTH", false),
		AllowInlineSecrets: boolEnv("CORDUM_ANTHROPIC_ALLOW_INLINE_SECRETS", false),
		DefaultProfile:     strings.TrimSpace(os.Getenv("CORDUM_ANTHROPIC_DEFAULT_PROFILE")),
		Profiles:           map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_ANTHROPIC_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_ANTHROPIC_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_ANTHROPIC_REQUEST_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.RequestTimeout = d
		}
	}

	cfg.AllowedModels = splitList(os.Getenv("CORDUM_ANTHROPIC_ALLOWED_MODELS"))
	cfg.DeniedModels = splitList(os.Getenv("CORDUM_ANTHROPIC_DENIED_MODELS"))

	// Profile loading from JSON env var
	if raw := strings.TrimSpace(os.Getenv("CORDUM_ANTHROPIC_PROFILES")); raw != "" {
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

	// Default profile from env vars if no profiles specified
	if len(cfg.Profiles) == 0 {
		defaultProfile := normalizeProfile(Profile{
			Name:              "default",
			BaseURL:           cfg.BaseURL,
			APIKey:            cfg.APIKey,
			APIKeyEnv:         strings.TrimSpace(os.Getenv("CORDUM_ANTHROPIC_API_KEY_ENV")),
			APIVersion:        cfg.APIVersion,
			AllowedModels:     cfg.AllowedModels,
			DeniedModels:      cfg.DeniedModels,
			MaxTokensLimit:    cfg.MaxTokensLimit,
			ThinkingEnabled:   cfg.ThinkingEnabled,
			ThinkingMaxBudget: cfg.ThinkingMaxBudget,
			UserAgent:         cfg.UserAgent,
		}, cfg)
		cfg.Profiles[defaultProfile.Name] = defaultProfile
	}

	// Resolve default profile
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

	return cfg, nil
}

// ResolveProfile returns the named profile or the default.
func (c Config) ResolveProfile(name string) Profile {
	if name != "" {
		if p, ok := c.Profiles[name]; ok {
			return p
		}
	}
	if p, ok := c.Profiles[c.DefaultProfile]; ok {
		return p
	}
	return Profile{
		Name:       "default",
		BaseURL:    c.BaseURL,
		APIKey:     c.APIKey,
		APIVersion: c.APIVersion,
		UserAgent:  c.UserAgent,
	}
}

// ResolveAPIKey returns the effective API key for a profile, checking env var fallback.
func (p Profile) ResolveAPIKey() string {
	if p.APIKey != "" {
		return p.APIKey
	}
	if p.APIKeyEnv != "" {
		return strings.TrimSpace(os.Getenv(p.APIKeyEnv))
	}
	return ""
}

// IsModelAllowed checks whether a model is permitted by the profile.
func (p Profile) IsModelAllowed(model string) bool {
	if len(p.DeniedModels) > 0 {
		for _, denied := range p.DeniedModels {
			if strings.EqualFold(denied, model) {
				return false
			}
		}
	}
	if len(p.AllowedModels) > 0 {
		for _, allowed := range p.AllowedModels {
			if strings.EqualFold(allowed, model) {
				return true
			}
		}
		return false
	}
	return true
}

func normalizeProfile(p Profile, cfg Config) Profile {
	if p.BaseURL == "" {
		p.BaseURL = cfg.BaseURL
	}
	if p.APIVersion == "" {
		p.APIVersion = cfg.APIVersion
	}
	if p.MaxTokensLimit <= 0 {
		p.MaxTokensLimit = cfg.MaxTokensLimit
	}
	if p.ThinkingMaxBudget <= 0 {
		p.ThinkingMaxBudget = cfg.ThinkingMaxBudget
	}
	if p.UserAgent == "" {
		p.UserAgent = cfg.UserAgent
	}
	return p
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func intEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func parseDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func splitList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
