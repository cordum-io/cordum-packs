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
	defaultPool           = "hello-pack"
	defaultQueue          = "hello-pack"
	defaultSubject        = "job.hello-pack.*"
	defaultRequestTimeout = 15 * time.Second
)

type Config struct {
	GatewayURL     string
	APIKey         string
	NatsURL        string
	RedisURL       string
	Pool           string
	Queue          string
	Subjects       []string
	MaxParallel    int32
	RequestTimeout time.Duration
	ResultTTL      time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:         envOr("CORDUM_API_KEY", ""),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_HELLO_PACK_POOL", defaultPool),
		Queue:          envOr("CORDUM_HELLO_PACK_QUEUE", defaultQueue),
		RequestTimeout: durationEnv("CORDUM_HELLO_PACK_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      durationEnv("CORDUM_HELLO_PACK_RESULT_TTL", 0),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_HELLO_PACK_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_HELLO_PACK_MAX_PARALLEL")); raw != "" {
		if val, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(val)
		}
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
	if raw == "" {
		return nil
	}
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

func durationEnv(key string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if val, err := time.ParseDuration(raw); err == nil {
			return val
		}
	}
	return fallback
}
