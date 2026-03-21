package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL      = "http://localhost:8081"
	defaultNatsURL         = "nats://localhost:4222"
	defaultRedisURL        = "redis://localhost:6379"
	defaultPool            = "crewai"
	defaultQueue           = "crewai"
	defaultSubject         = "job.crewai.*"
	defaultToolTopic       = "job.crewai.toolcall"
	defaultSidecarCommand  = "python"
	defaultCrewTimeout     = 300 * time.Second
	defaultCallbackTimeout = 2 * time.Minute
)

type Config struct {
	GatewayURL     string
	APIKey         string // #nosec G101 -- runtime-supplied credential field; no hardcoded secret value
	TenantID       string
	NatsURL        string
	RedisURL       string
	Pool           string
	Queue          string
	Subjects       []string
	MaxParallel    int32
	RequestTimeout time.Duration
	ResultTTL      time.Duration

	CallbackPort        int
	CallbackWaitTimeout time.Duration
	ToolTopic           string

	SidecarCommand    string
	SidecarArgs       []string
	SidecarPythonPath string
	MaxRPM            int
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL:          envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:              strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:            envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:             envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:            envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:                envOr("CORDUM_CREWAI_POOL", defaultPool),
		Queue:               envOr("CORDUM_CREWAI_QUEUE", defaultQueue),
		RequestTimeout:      parseDuration("CORDUM_CREWAI_TIMEOUT", "CORDUM_CREWAI_TIMEOUT_SECONDS", defaultCrewTimeout),
		ResultTTL:           parseDuration("CORDUM_CREWAI_RESULT_TTL", "CORDUM_CREWAI_RESULT_TTL_SECONDS", 0),
		CallbackPort:        intEnv("CORDUM_CREWAI_CALLBACK_PORT", 0),
		CallbackWaitTimeout: parseDuration("CORDUM_CREWAI_CALLBACK_WAIT_TIMEOUT", "CORDUM_CREWAI_CALLBACK_WAIT_TIMEOUT_SECONDS", defaultCallbackTimeout),
		ToolTopic:           envOr("CORDUM_CREWAI_TOOL_TOPIC", defaultToolTopic),
		SidecarCommand:      envOr("CORDUM_CREWAI_SIDECAR_COMMAND", defaultSidecarCommand),
		SidecarArgs:         splitArgs(envOr("CORDUM_CREWAI_SIDECAR_ARGS", "-m,cordum_crewai_sidecar")),
		SidecarPythonPath:   strings.TrimSpace(os.Getenv("CORDUM_CREWAI_SIDECAR_PYTHONPATH")),
		MaxRPM:              intEnv("CORDUM_CREWAI_MAX_RPM", 0),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_CREWAI_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_CREWAI_MAX_PARALLEL")); raw != "" {
		if value, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(value)
		}
	}
	if cfg.SidecarPythonPath == "" {
		cfg.SidecarPythonPath = defaultPythonPath()
	}

	return cfg, nil
}

func defaultPythonPath() string {
	existing := strings.TrimSpace(os.Getenv("PYTHONPATH"))
	cwd, err := os.Getwd()
	if err != nil || strings.TrimSpace(cwd) == "" {
		return existing
	}

	entries := []string{
		filepath.Join(cwd, "sidecar"),
		filepath.Join(cwd, "..", "..", "integrations", "agent-adapters"),
	}
	if existing != "" {
		entries = append(entries, existing)
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return strings.Join(out, string(os.PathListSeparator))
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitArgs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return splitList(raw)
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			return value
		}
	}
	return fallback
}

func parseDuration(primaryKey, secondsKey string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(primaryKey)); raw != "" {
		if value, err := time.ParseDuration(raw); err == nil {
			return value
		}
	}
	if raw := strings.TrimSpace(os.Getenv(secondsKey)); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			return time.Duration(value) * time.Second
		}
	}
	return fallback
}
