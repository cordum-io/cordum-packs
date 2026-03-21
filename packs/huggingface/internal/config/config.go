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
	defaultPool           = "huggingface"
	defaultSubject        = "job.huggingface.*"
	defaultInferenceURL   = "https://api-inference.huggingface.co"
	defaultHubURL         = "https://huggingface.co/api"
	defaultRequestTimeout = 120 * time.Second
)

// Config holds all HuggingFace pack configuration.
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
	InferenceURL   string
	HubURL         string
	Token          string // #nosec G117
	AllowedTasks   []string
	DeniedTasks    []string
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		TenantID:       envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_HUGGINGFACE_POOL", defaultPool),
		RequestTimeout: parseDuration("CORDUM_HUGGINGFACE_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      parseDuration("CORDUM_HUGGINGFACE_RESULT_TTL", 0),
		InferenceURL:   envOr("CORDUM_HUGGINGFACE_INFERENCE_URL", defaultInferenceURL),
		HubURL:         envOr("CORDUM_HUGGINGFACE_HUB_URL", defaultHubURL),
		Token:          strings.TrimSpace(os.Getenv("HF_TOKEN")),
		AllowedTasks:   splitList(os.Getenv("CORDUM_HUGGINGFACE_ALLOWED_TASKS")),
		DeniedTasks:    splitList(os.Getenv("CORDUM_HUGGINGFACE_DENIED_TASKS")),
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_HUGGINGFACE_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_HUGGINGFACE_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}
	return cfg, nil
}

// IsTaskAllowed checks whether a task type is permitted.
func (c Config) IsTaskAllowed(task string) bool {
	if task == "" {
		return true
	}
	if len(c.DeniedTasks) > 0 {
		for _, d := range c.DeniedTasks {
			if strings.EqualFold(d, task) {
				return false
			}
		}
	}
	if len(c.AllowedTasks) > 0 {
		for _, a := range c.AllowedTasks {
			if strings.EqualFold(a, task) {
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
