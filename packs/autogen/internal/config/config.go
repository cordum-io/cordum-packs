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
	defaultPool           = "autogen"
	defaultSubject        = "job.autogen.*"
	defaultRequestTimeout = 300 * time.Second
	defaultPythonCommand  = "python"
	defaultSidecarModule  = "cordum_autogen_sidecar"
	defaultDockerImage    = "python:3.12-slim"
	defaultCodeTimeout    = 30
	defaultMaxRounds      = 20
)

// Config holds all AutoGen pack configuration.
type Config struct {
	GatewayURL       string
	APIKey           string
	TenantID         string
	NatsURL          string
	RedisURL         string
	Pool             string
	Subjects         []string
	MaxParallel      int32
	RequestTimeout   time.Duration
	ResultTTL        time.Duration
	PythonCommand    string
	SidecarModule    string
	SidecarPort      int
	SidecarEnv       map[string]string
	ToolGovernance   bool
	ToolCallTopic    string
	CapabilityPrefix string
	CodeExecution    string // "docker", "local", "disabled"
	DockerImage      string
	CodeTimeout      int
	MaxRounds        int
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:       envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:           strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:         envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:          envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:         envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:             envOr("CORDUM_AUTOGEN_POOL", defaultPool),
		RequestTimeout:   parseDuration("CORDUM_AUTOGEN_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:        parseDuration("CORDUM_AUTOGEN_RESULT_TTL", 0),
		PythonCommand:    envOr("CORDUM_AUTOGEN_PYTHON_CMD", defaultPythonCommand),
		SidecarModule:    envOr("CORDUM_AUTOGEN_SIDECAR_MODULE", defaultSidecarModule),
		SidecarPort:      intEnv("CORDUM_AUTOGEN_SIDECAR_PORT", 0),
		ToolGovernance:   boolEnv("CORDUM_AUTOGEN_TOOL_GOVERNANCE", true),
		ToolCallTopic:    envOr("CORDUM_AUTOGEN_TOOLCALL_TOPIC", "job.autogen.toolcall"),
		CapabilityPrefix: envOr("CORDUM_AUTOGEN_CAPABILITY_PREFIX", "autogen"),
		CodeExecution:    envOr("CORDUM_AUTOGEN_CODE_EXECUTION", "docker"),
		DockerImage:      envOr("CORDUM_AUTOGEN_DOCKER_IMAGE", defaultDockerImage),
		CodeTimeout:      intEnv("CORDUM_AUTOGEN_CODE_TIMEOUT", defaultCodeTimeout),
		MaxRounds:        intEnv("CORDUM_AUTOGEN_MAX_ROUNDS", defaultMaxRounds),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_AUTOGEN_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_AUTOGEN_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	cfg.SidecarEnv = map[string]string{
		"CORDUM_AUTOGEN_CODE_EXECUTION": cfg.CodeExecution,
		"CORDUM_AUTOGEN_DOCKER_IMAGE":   cfg.DockerImage,
		"CORDUM_AUTOGEN_CODE_TIMEOUT":   strconv.Itoa(cfg.CodeTimeout),
		"CORDUM_AUTOGEN_MAX_ROUNDS":     strconv.Itoa(cfg.MaxRounds),
	}
	for _, key := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY"} {
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
