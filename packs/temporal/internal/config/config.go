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
	defaultPool           = "temporal"
	defaultSubject        = "job.temporal.*"
	defaultTemporalHost   = "localhost:7233"
	defaultNamespace      = "default"
	defaultRequestTimeout = 30 * time.Second
)

// Config holds all Temporal pack configuration.
type Config struct {
	GatewayURL        string
	TenantID          string
	NatsURL           string
	RedisURL          string
	Pool              string
	Subjects          []string
	MaxParallel       int32
	RequestTimeout    time.Duration
	ResultTTL         time.Duration
	TemporalHost      string
	Namespace         string
	Identity          string
	TLSCertPath       string
	TLSKeyPath        string
	TLSCAPath         string
	APIKey            string // Temporal Cloud API key
	AllowedTaskQueues []string
	DeniedTaskQueues  []string
	AllowedWorkflows  []string
	DeniedWorkflows   []string
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:        envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		TenantID:          envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:           envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:          envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:              envOr("CORDUM_TEMPORAL_POOL", defaultPool),
		RequestTimeout:    parseDuration("CORDUM_TEMPORAL_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:         parseDuration("CORDUM_TEMPORAL_RESULT_TTL", 0),
		TemporalHost:      envOr("TEMPORAL_ADDRESS", envOr("TEMPORAL_HOST", defaultTemporalHost)),
		Namespace:         envOr("TEMPORAL_NAMESPACE", defaultNamespace),
		Identity:          envOr("CORDUM_TEMPORAL_IDENTITY", "cordum-temporal-worker"),
		TLSCertPath:       strings.TrimSpace(os.Getenv("TEMPORAL_TLS_CERT")),
		TLSKeyPath:        strings.TrimSpace(os.Getenv("TEMPORAL_TLS_KEY")),
		TLSCAPath:         strings.TrimSpace(os.Getenv("TEMPORAL_TLS_CA")),
		APIKey:            strings.TrimSpace(os.Getenv("TEMPORAL_API_KEY")),
		AllowedTaskQueues: splitList(os.Getenv("CORDUM_TEMPORAL_ALLOWED_TASK_QUEUES")),
		DeniedTaskQueues:  splitList(os.Getenv("CORDUM_TEMPORAL_DENIED_TASK_QUEUES")),
		AllowedWorkflows:  splitList(os.Getenv("CORDUM_TEMPORAL_ALLOWED_WORKFLOWS")),
		DeniedWorkflows:   splitList(os.Getenv("CORDUM_TEMPORAL_DENIED_WORKFLOWS")),
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_TEMPORAL_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_TEMPORAL_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}
	return cfg, nil
}

// IsTaskQueueAllowed checks if a task queue is permitted.
func (c Config) IsTaskQueueAllowed(queue string) bool {
	if queue == "" {
		return true
	}
	return isAllowed(queue, c.AllowedTaskQueues, c.DeniedTaskQueues)
}

// IsWorkflowAllowed checks if a workflow type is permitted.
func (c Config) IsWorkflowAllowed(wfType string) bool {
	if wfType == "" {
		return true
	}
	return isAllowed(wfType, c.AllowedWorkflows, c.DeniedWorkflows)
}

func isAllowed(value string, allowList, denyList []string) bool {
	if len(denyList) > 0 {
		for _, d := range denyList {
			if strings.EqualFold(d, value) {
				return false
			}
		}
	}
	if len(allowList) > 0 {
		for _, a := range allowList {
			if strings.EqualFold(a, value) {
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
