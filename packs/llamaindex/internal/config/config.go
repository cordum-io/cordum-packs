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
	defaultPool           = "llamaindex"
	defaultSubject        = "job.llamaindex.*"
	defaultRequestTimeout = 300 * time.Second
	defaultPythonCommand  = "python"
	defaultSidecarModule  = "cordum_llamaindex_sidecar"
	defaultStorageDir     = "./llamaindex_storage"
)

// Config holds all LlamaIndex pack configuration.
type Config struct {
	GatewayURL     string
	APIKey         string
	TenantID       string
	NatsURL        string
	RedisURL       string
	Pool           string
	Subjects       []string
	MaxParallel    int32
	RequestTimeout time.Duration
	ResultTTL      time.Duration
	PythonCommand  string
	SidecarModule  string
	SidecarPort    int
	SidecarEnv     map[string]string
	StorageDir     string
	DefaultBackend string
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:         strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:       envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_LLAMAINDEX_POOL", defaultPool),
		RequestTimeout: parseDuration("CORDUM_LLAMAINDEX_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      parseDuration("CORDUM_LLAMAINDEX_RESULT_TTL", 0),
		PythonCommand:  envOr("CORDUM_LLAMAINDEX_PYTHON_CMD", defaultPythonCommand),
		SidecarModule:  envOr("CORDUM_LLAMAINDEX_SIDECAR_MODULE", defaultSidecarModule),
		SidecarPort:    intEnv("CORDUM_LLAMAINDEX_SIDECAR_PORT", 0),
		StorageDir:     envOr("CORDUM_LLAMAINDEX_STORAGE_DIR", defaultStorageDir),
		DefaultBackend: envOr("CORDUM_LLAMAINDEX_DEFAULT_BACKEND", "chroma"),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_LLAMAINDEX_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_LLAMAINDEX_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	cfg.SidecarEnv = map[string]string{}
	for _, key := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY", "HF_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			cfg.SidecarEnv[key] = v
		}
	}

	return cfg, nil
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
