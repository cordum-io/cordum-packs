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
	defaultPool           = "bedrock"
	defaultSubject        = "job.bedrock.*"
	defaultRegion         = "us-east-1"
	defaultRequestTimeout = 120 * time.Second
)

// Config holds all Bedrock pack configuration.
type Config struct {
	GatewayURL      string
	TenantID        string
	NatsURL         string
	RedisURL        string
	Pool            string
	Subjects        []string
	MaxParallel     int32
	RequestTimeout  time.Duration
	ResultTTL       time.Duration
	DefaultRegion   string
	AllowedModels   []string
	DeniedModels    []string
	MaxTokensLimit  int
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		TenantID:       envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_BEDROCK_POOL", defaultPool),
		RequestTimeout: parseDuration("CORDUM_BEDROCK_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      parseDuration("CORDUM_BEDROCK_RESULT_TTL", 0),
		DefaultRegion:  envOr("AWS_REGION", envOr("AWS_DEFAULT_REGION", defaultRegion)),
		AllowedModels:  splitList(os.Getenv("CORDUM_BEDROCK_ALLOWED_MODELS")),
		DeniedModels:   splitList(os.Getenv("CORDUM_BEDROCK_DENIED_MODELS")),
		MaxTokensLimit: intEnv("CORDUM_BEDROCK_MAX_TOKENS", 128000),
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_BEDROCK_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_BEDROCK_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}
	return cfg, nil
}

// IsModelAllowed checks whether a model ID is permitted.
func (c Config) IsModelAllowed(modelID string) bool {
	if modelID == "" {
		return true
	}
	if len(c.DeniedModels) > 0 {
		for _, d := range c.DeniedModels {
			if strings.EqualFold(d, modelID) || strings.Contains(strings.ToLower(modelID), strings.ToLower(d)) {
				return false
			}
		}
	}
	if len(c.AllowedModels) > 0 {
		for _, a := range c.AllowedModels {
			if strings.EqualFold(a, modelID) || strings.Contains(strings.ToLower(modelID), strings.ToLower(a)) {
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
