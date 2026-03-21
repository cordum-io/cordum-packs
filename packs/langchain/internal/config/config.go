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
	defaultPool           = "langchain"
	defaultQueue          = "langchain"
	defaultSubject        = "job.langchain.*"
	defaultRequestTimeout = 300 * time.Second
	defaultPythonCommand  = "python"
	defaultSidecarModule  = "cordum_langchain_sidecar"
)

// Config holds all LangChain pack configuration.
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

	// Sidecar
	PythonCommand string
	SidecarModule string
	SidecarPort   int
	SidecarEnv    map[string]string

	// Governance
	ToolGovernance   bool
	ToolCallTopic    string
	CapabilityPrefix string
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:         strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:       envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_LANGCHAIN_POOL", defaultPool),
		Queue:          envOr("CORDUM_LANGCHAIN_QUEUE", defaultQueue),
		RequestTimeout: parseDuration("CORDUM_LANGCHAIN_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      parseDuration("CORDUM_LANGCHAIN_RESULT_TTL", 0),

		PythonCommand:    envOr("CORDUM_LANGCHAIN_PYTHON_CMD", defaultPythonCommand),
		SidecarModule:    envOr("CORDUM_LANGCHAIN_SIDECAR_MODULE", defaultSidecarModule),
		SidecarPort:      intEnv("CORDUM_LANGCHAIN_SIDECAR_PORT", 0),
		ToolGovernance:   boolEnv("CORDUM_LANGCHAIN_TOOL_GOVERNANCE", true),
		ToolCallTopic:    envOr("CORDUM_LANGCHAIN_TOOLCALL_TOPIC", "job.langchain.toolcall"),
		CapabilityPrefix: envOr("CORDUM_LANGCHAIN_CAPABILITY_PREFIX", "langchain"),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_LANGCHAIN_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_LANGCHAIN_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	// Sidecar environment — pass through LLM API keys
	cfg.SidecarEnv = map[string]string{}
	for _, key := range []string{
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MISTRAL_API_KEY",
		"COHERE_API_KEY", "HUGGINGFACE_API_KEY",
	} {
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
