package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL     = "http://localhost:8081"
	defaultNatsURL        = "nats://localhost:4222"
	defaultRedisURL       = "redis://localhost:6379"
	defaultPool           = "datadog"
	defaultQueue          = "datadog"
	defaultSubject        = "job.datadog.*"
	defaultBaseURL        = "https://api.datadoghq.com"
	defaultUserAgent      = "cordum-datadog-worker/0.1.0"
	defaultRequestTimeout = 30 * time.Second
)

type Profile struct {
	Name          string            `json:"name"`
	BaseURL       string            `json:"base_url"`
	APIKey        string            `json:"api_key"`
	APIKeyEnv     string            `json:"api_key_env"`
	AppKey        string            `json:"app_key"`
	AppKeyEnv     string            `json:"app_key_env"`
	AllowActions  []string          `json:"allow_actions"`
	DenyActions   []string          `json:"deny_actions"`
	Headers       map[string]string `json:"headers"`
	UserAgent     string            `json:"user_agent"`
	Timeout       time.Duration     `json:"-"`
	TimeoutString string            `json:"timeout"`
}

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
	DefaultProfile string
	Profiles       map[string]Profile
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:         envOr("CORDUM_API_KEY", ""),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_DATADOG_POOL", defaultPool),
		Queue:          envOr("CORDUM_DATADOG_QUEUE", defaultQueue),
		RequestTimeout: defaultRequestTimeout,
		ResultTTL:      durationEnv("CORDUM_DATADOG_RESULT_TTL", 0),
		DefaultProfile: strings.TrimSpace(os.Getenv("CORDUM_DATADOG_DEFAULT_PROFILE")),
		Profiles:       map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_DATADOG_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_DATADOG_MAX_PARALLEL")); raw != "" {
		if val, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(val)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_DATADOG_REQUEST_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.RequestTimeout = d
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_DATADOG_PROFILES")); raw != "" {
		var profiles []Profile
		if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
			return cfg, err
		}
		for _, profile := range profiles {
			profile = normalizeProfile(profile)
			if strings.TrimSpace(profile.Name) == "" {
				continue
			}
			cfg.Profiles[profile.Name] = profile
		}
	}

	if len(cfg.Profiles) == 0 {
		defaultProfile := normalizeProfile(Profile{
			Name:         "default",
			BaseURL:      envOr("CORDUM_DATADOG_BASE_URL", defaultBaseURL),
			APIKey:       strings.TrimSpace(os.Getenv("CORDUM_DATADOG_API_KEY")),
			APIKeyEnv:    strings.TrimSpace(os.Getenv("CORDUM_DATADOG_API_KEY_ENV")),
			AppKey:       strings.TrimSpace(os.Getenv("CORDUM_DATADOG_APP_KEY")),
			AppKeyEnv:    strings.TrimSpace(os.Getenv("CORDUM_DATADOG_APP_KEY_ENV")),
			AllowActions: splitList(os.Getenv("CORDUM_DATADOG_ALLOW_ACTIONS")),
			DenyActions:  splitList(os.Getenv("CORDUM_DATADOG_DENY_ACTIONS")),
			Headers:      map[string]string{},
			UserAgent:    envOr("CORDUM_DATADOG_USER_AGENT", defaultUserAgent),
		})
		cfg.Profiles[defaultProfile.Name] = defaultProfile
	}

	if cfg.DefaultProfile == "" {
		if _, ok := cfg.Profiles["default"]; ok {
			cfg.DefaultProfile = "default"
		} else {
			for name := range cfg.Profiles {
				cfg.DefaultProfile = name
				break
			}
		}
	}

	return cfg, nil
}

func normalizeProfile(profile Profile) Profile {
	if strings.TrimSpace(profile.BaseURL) == "" {
		profile.BaseURL = defaultBaseURL
	}
	if strings.TrimSpace(profile.UserAgent) == "" {
		profile.UserAgent = defaultUserAgent
	}
	if profile.Headers == nil {
		profile.Headers = map[string]string{}
	}
	if raw := strings.TrimSpace(profile.TimeoutString); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			profile.Timeout = d
		}
	}
	return profile
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

func envOr(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			return d
		}
	}
	return fallback
}
