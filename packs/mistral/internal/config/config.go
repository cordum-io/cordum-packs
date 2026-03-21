package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL     = "http://localhost:8081"
	defaultNatsURL        = "nats://localhost:4222"
	defaultRedisURL       = "redis://localhost:6379"
	defaultPool           = "mistral"
	defaultSubject        = "job.mistral.*"
	defaultBaseURL        = "https://api.mistral.ai"
	defaultRequestTimeout = 120 * time.Second
	defaultMaxTokensLimit = 128000
)

// Config holds all Mistral pack configuration.
type Config struct {
	GatewayURL     string
	TenantID       string
	NatsURL        string
	RedisURL       string
	Pool           string
	Subjects       []string
	MaxParallel    int32
	RequestTimeout time.Duration
	ResultTTL      time.Duration

	BaseURL        string
	APIKey         string // #nosec G117
	AllowedModels  []string
	DeniedModels   []string
	MaxTokensLimit int
	SafePrompt     bool
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		TenantID:       envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_MISTRAL_POOL", defaultPool),
		RequestTimeout: parseDuration("CORDUM_MISTRAL_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      parseDuration("CORDUM_MISTRAL_RESULT_TTL", 0),

		BaseURL:        envOr("CORDUM_MISTRAL_BASE_URL", defaultBaseURL),
		APIKey:         strings.TrimSpace(os.Getenv("MISTRAL_API_KEY")),
		AllowedModels:  splitList(os.Getenv("CORDUM_MISTRAL_ALLOWED_MODELS")),
		DeniedModels:   splitList(os.Getenv("CORDUM_MISTRAL_DENIED_MODELS")),
		MaxTokensLimit: intEnv("CORDUM_MISTRAL_MAX_TOKENS_LIMIT", defaultMaxTokensLimit),
		SafePrompt:     boolEnv("CORDUM_MISTRAL_SAFE_PROMPT", false),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_MISTRAL_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_MISTRAL_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	return cfg, nil
}

// IsModelAllowed checks whether a model is permitted.
func (c Config) IsModelAllowed(model string) bool {
	if len(c.DeniedModels) > 0 {
		for _, d := range c.DeniedModels {
			if strings.EqualFold(d, model) {
				return false
			}
		}
	}
	if len(c.AllowedModels) > 0 {
		for _, a := range c.AllowedModels {
			if strings.EqualFold(a, model) {
				return true
			}
		}
		return false
	}
	return true
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
