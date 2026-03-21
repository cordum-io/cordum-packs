package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL     = "http://localhost:8081"
	defaultNatsURL        = "nats://localhost:4222"
	defaultRedisURL       = "redis://localhost:6379"
	defaultPool           = "openai"
	defaultQueue          = "openai"
	defaultSubject        = "job.openai.*"
	defaultBaseURL        = "https://api.openai.com/v1"
	defaultRequestTimeout = 90 * time.Second
)

type Profile struct {
	Name            string            `json:"name"`
	BaseURL         string            `json:"base_url"`
	APIKey          string            `json:"api_key"` // #nosec G101 -- runtime-supplied credential field; no hardcoded secret value
	APIKeyEnv       string            `json:"api_key_env"`
	Organization    string            `json:"organization"`
	OrganizationEnv string            `json:"organization_env"`
	AllowedModels   []string          `json:"allowed_models"`
	DeniedModels    []string          `json:"denied_models"`
	MaxTokensLimit  int               `json:"max_tokens_limit"`
	CostTracking    *bool             `json:"cost_tracking"`
	RateLimitRetry  *bool             `json:"rate_limit_retry"`
	MaxRetries      *int              `json:"max_retries"`
	Headers         map[string]string `json:"headers"`
	Timeout         time.Duration     `json:"-"`
	TimeoutString   string            `json:"timeout"`
}

type Config struct {
	GatewayURL         string
	GatewayAPIKey      string // #nosec G101 -- runtime-supplied credential field; no hardcoded secret value
	TenantID           string
	NatsURL            string
	RedisURL           string
	Pool               string
	Queue              string
	Subjects           []string
	MaxParallel        int32
	RequestTimeout     time.Duration
	ResultTTL          time.Duration
	AllowInlineAuth    bool
	AllowInlineSecrets bool

	BaseURL        string
	APIKey         string // #nosec G101 -- runtime-supplied credential field; no hardcoded secret value
	Organization   string
	AllowedModels  []string
	DeniedModels   []string
	MaxTokensLimit int
	CostTracking   bool
	RateLimitRetry bool
	MaxRetries     int

	DefaultProfile string
	Profiles       map[string]Profile
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL:         envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		GatewayAPIKey:      strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:           envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:            envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:           envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:               envOr("CORDUM_OPENAI_POOL", defaultPool),
		Queue:              envOr("CORDUM_OPENAI_QUEUE", defaultQueue),
		RequestTimeout:     parseDuration("CORDUM_OPENAI_REQUEST_TIMEOUT", "CORDUM_OPENAI_REQUEST_TIMEOUT_SECONDS", defaultRequestTimeout),
		ResultTTL:          parseDuration("CORDUM_OPENAI_RESULT_TTL", "CORDUM_OPENAI_RESULT_TTL_SECONDS", 0),
		AllowInlineAuth:    boolEnv("CORDUM_OPENAI_ALLOW_INLINE_AUTH", false),
		AllowInlineSecrets: boolEnv("CORDUM_OPENAI_ALLOW_INLINE_SECRETS", false),
		BaseURL:            envOr("CORDUM_OPENAI_BASE_URL", defaultBaseURL),
		APIKey:             strings.TrimSpace(os.Getenv("CORDUM_OPENAI_API_KEY")),
		Organization:       strings.TrimSpace(os.Getenv("CORDUM_OPENAI_ORGANIZATION")),
		AllowedModels:      splitList(os.Getenv("CORDUM_OPENAI_ALLOWED_MODELS")),
		DeniedModels:       splitList(os.Getenv("CORDUM_OPENAI_DENIED_MODELS")),
		MaxTokensLimit:     intEnv("CORDUM_OPENAI_MAX_TOKENS_LIMIT", 0),
		CostTracking:       boolEnv("CORDUM_OPENAI_COST_TRACKING", true),
		RateLimitRetry:     boolEnv("CORDUM_OPENAI_RATE_LIMIT_RETRY", true),
		MaxRetries:         intEnv("CORDUM_OPENAI_MAX_RETRIES", 2),
		DefaultProfile:     strings.TrimSpace(os.Getenv("CORDUM_OPENAI_DEFAULT_PROFILE")),
		Profiles:           map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_OPENAI_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_OPENAI_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_OPENAI_PROFILES")); raw != "" {
		var profiles []Profile
		if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
			return cfg, fmt.Errorf("parse CORDUM_OPENAI_PROFILES: %w", err)
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
		profile := normalizeProfile(Profile{
			Name:            "default",
			BaseURL:         cfg.BaseURL,
			APIKey:          cfg.APIKey,
			APIKeyEnv:       strings.TrimSpace(os.Getenv("CORDUM_OPENAI_API_KEY_ENV")),
			Organization:    cfg.Organization,
			OrganizationEnv: strings.TrimSpace(os.Getenv("CORDUM_OPENAI_ORGANIZATION_ENV")),
			AllowedModels:   append([]string(nil), cfg.AllowedModels...),
			DeniedModels:    append([]string(nil), cfg.DeniedModels...),
			MaxTokensLimit:  cfg.MaxTokensLimit,
			CostTracking:    boolPtr(cfg.CostTracking),
			RateLimitRetry:  boolPtr(cfg.RateLimitRetry),
			MaxRetries:      intPtr(cfg.MaxRetries),
			Headers:         map[string]string{},
			Timeout:         cfg.RequestTimeout,
		}, cfg)
		cfg.Profiles[profile.Name] = profile
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

	if cfg.DefaultProfile == "" {
		return cfg, fmt.Errorf("default profile not configured")
	}
	return cfg, nil
}

func normalizeProfile(profile Profile, cfg Config) Profile {
	if strings.TrimSpace(profile.BaseURL) == "" {
		profile.BaseURL = cfg.BaseURL
	}
	if profile.MaxTokensLimit == 0 {
		profile.MaxTokensLimit = cfg.MaxTokensLimit
	}
	if profile.CostTracking == nil {
		profile.CostTracking = boolPtr(cfg.CostTracking)
	}
	if profile.RateLimitRetry == nil {
		profile.RateLimitRetry = boolPtr(cfg.RateLimitRetry)
	}
	if profile.MaxRetries == nil {
		profile.MaxRetries = intPtr(cfg.MaxRetries)
	}
	if profile.Headers == nil {
		profile.Headers = map[string]string{}
	}
	if len(profile.AllowedModels) == 0 && len(cfg.AllowedModels) > 0 {
		profile.AllowedModels = append([]string(nil), cfg.AllowedModels...)
	}
	if len(profile.DeniedModels) == 0 && len(cfg.DeniedModels) > 0 {
		profile.DeniedModels = append([]string(nil), cfg.DeniedModels...)
	}
	if raw := strings.TrimSpace(profile.TimeoutString); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			profile.Timeout = d
		}
	}
	if profile.Timeout == 0 {
		profile.Timeout = cfg.RequestTimeout
	}
	return profile
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
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

func envOr(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "y":
			return true
		case "0", "false", "no", "n":
			return false
		}
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			return v
		}
	}
	return fallback
}

func parseDuration(primaryKey, secondsKey string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(primaryKey)); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			return d
		}
	}
	if raw := strings.TrimSpace(os.Getenv(secondsKey)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return fallback
}

func boolPtr(v bool) *bool {
	return &v
}

func intPtr(v int) *int {
	return &v
}
