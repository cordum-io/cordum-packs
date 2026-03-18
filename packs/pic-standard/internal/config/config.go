package config

import (
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
	defaultPool           = "pic-standard-primary"
	defaultQueue          = "pic-standard"
	defaultSubject        = "job.pic-standard.verify"
	defaultRequestTimeout = 15 * time.Second
	defaultBridgeURL      = "http://localhost:3100"
	defaultBridgeTimeout  = 5 * time.Second
	defaultLogLevel       = "info"
	defaultMaxParallel    = int32(8)
)

type Config struct {
	// Common Cordum settings
	GatewayURL     string
	APIKey         string // #nosec G117 -- runtime-supplied credential field; no hardcoded secret
	TenantID       string
	NatsURL        string
	RedisURL       string
	Pool           string
	Queue          string
	Subjects       []string
	MaxParallel    int32
	RequestTimeout time.Duration
	ResultTTL      time.Duration

	// PIC-specific settings
	BridgeURL              string
	BridgeTimeout          time.Duration
	BridgeToken            string // #nosec G117 -- runtime-supplied credential field; no hardcoded secret
	LogLevel               string
	RequireApprovalImpacts []string
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL: envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:     envOr("CORDUM_API_KEY", ""),
		TenantID:   envOr("CORDUM_TENANT_ID", "default"),

		// Prefer CAP SDK defaults, fall back to Cordum-prefixed
		NatsURL:  envOr("NATS_URL", envOr("CORDUM_NATS_URL", defaultNatsURL)),
		RedisURL: envOr("REDIS_URL", envOr("CORDUM_REDIS_URL", defaultRedisURL)),

		Pool:        envOr("CORDUM_PIC_STANDARD_POOL", defaultPool),
		Queue:       envOr("CORDUM_PIC_STANDARD_QUEUE", defaultQueue),
		MaxParallel: defaultMaxParallel,

		RequestTimeout: defaultRequestTimeout,
		ResultTTL:      0,

		BridgeURL:     envOr("CORDUM_PIC_STANDARD_BRIDGE_URL", defaultBridgeURL),
		BridgeTimeout: defaultBridgeTimeout,
		BridgeToken:   envOr("CORDUM_PIC_STANDARD_BRIDGE_TOKEN", ""),
		LogLevel:      envOr("CORDUM_PIC_STANDARD_LOG_LEVEL", defaultLogLevel),

		RequireApprovalImpacts: []string{},
	}

	if strings.TrimSpace(cfg.BridgeURL) == "" {
		return Config{}, fmt.Errorf("CORDUM_PIC_STANDARD_BRIDGE_URL is empty")
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_PIC_STANDARD_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if d, err := durationEnvStrict("CORDUM_PIC_STANDARD_REQUEST_TIMEOUT"); err != nil {
		return Config{}, err
	} else if d != nil {
		cfg.RequestTimeout = *d
	}

	if d, err := durationEnvStrict("CORDUM_PIC_STANDARD_RESULT_TTL"); err != nil {
		return Config{}, err
	} else if d != nil {
		cfg.ResultTTL = *d
	}

	if d, err := durationEnvStrict("CORDUM_PIC_STANDARD_BRIDGE_TIMEOUT"); err != nil {
		return Config{}, err
	} else if d != nil {
		cfg.BridgeTimeout = *d
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_PIC_STANDARD_MAX_PARALLEL")); raw != "" {
		val, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || val < 1 {
			return Config{}, fmt.Errorf("invalid CORDUM_PIC_STANDARD_MAX_PARALLEL: %q", raw)
		}
		cfg.MaxParallel = int32(val)
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_PIC_STANDARD_REQUIRE_APPROVAL_IMPACTS")); raw != "" {
		cfg.RequireApprovalImpacts = splitList(raw)
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		val := strings.TrimSpace(part)
		if val != "" {
			out = append(out, val)
		}
	}
	return out
}

// durationEnvStrict returns (*duration, nil) if set and parsed,
// (nil, nil) if unset, or (nil, error) if set but invalid.
func durationEnvStrict(key string) (*time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil, nil
	}
	val, err := time.ParseDuration(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s duration %q: %w", key, raw, err)
	}
	return &val, nil
}
