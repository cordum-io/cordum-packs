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
	defaultPool           = "slack"
	defaultQueue          = "slack"
	defaultSubject        = "job.slack.*"
	defaultBaseURL        = "https://slack.com/api"
	defaultUserAgent      = "cordum-slack-worker/0.1.0"
	defaultRequestTimeout = 45 * time.Second
)

type Profile struct {
	Name            string            `json:"name"`
	BaseURL         string            `json:"base_url"`
	Token           string            `json:"token"`
	TokenEnv        string            `json:"token_env"`
	AllowedChannels []string          `json:"allowed_channels"`
	DeniedChannels  []string          `json:"denied_channels"`
	AllowActions    []string          `json:"allow_actions"`
	DenyActions     []string          `json:"deny_actions"`
	Headers         map[string]string `json:"headers"`
	UserAgent       string            `json:"user_agent"`
	Timeout         time.Duration     `json:"-"`
	TimeoutString   string            `json:"timeout"`
}

type Config struct {
	GatewayURL      string
	APIKey          string
	NatsURL         string
	RedisURL        string
	Pool            string
	Queue           string
	Subjects        []string
	MaxParallel     int32
	RequestTimeout  time.Duration
	ResultTTL       time.Duration
	AllowInlineAuth bool
	DefaultProfile  string
	Profiles        map[string]Profile
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL:      envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:          envOr("CORDUM_API_KEY", ""),
		NatsURL:         envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:        envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:            envOr("CORDUM_SLACK_POOL", defaultPool),
		Queue:           envOr("CORDUM_SLACK_QUEUE", defaultQueue),
		RequestTimeout:  defaultRequestTimeout,
		ResultTTL:       parseDuration("CORDUM_SLACK_RESULT_TTL", "CORDUM_SLACK_RESULT_TTL_SECONDS", 0),
		AllowInlineAuth: boolEnv("CORDUM_SLACK_ALLOW_INLINE_AUTH", false),
		DefaultProfile:  strings.TrimSpace(os.Getenv("CORDUM_SLACK_DEFAULT_PROFILE")),
		Profiles:        map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_SLACK_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_SLACK_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_SLACK_REQUEST_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.RequestTimeout = d
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_SLACK_PROFILES")); raw != "" {
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
			Name:            "default",
			BaseURL:         envOr("CORDUM_SLACK_BASE_URL", defaultBaseURL),
			Token:           strings.TrimSpace(os.Getenv("CORDUM_SLACK_TOKEN")),
			TokenEnv:        strings.TrimSpace(os.Getenv("CORDUM_SLACK_TOKEN_ENV")),
			AllowedChannels: splitList(os.Getenv("CORDUM_SLACK_ALLOWED_CHANNELS")),
			DeniedChannels:  splitList(os.Getenv("CORDUM_SLACK_DENIED_CHANNELS")),
			AllowActions:    splitList(os.Getenv("CORDUM_SLACK_ALLOW_ACTIONS")),
			DenyActions:     splitList(os.Getenv("CORDUM_SLACK_DENY_ACTIONS")),
			Headers:         map[string]string{},
			UserAgent:       envOr("CORDUM_SLACK_USER_AGENT", defaultUserAgent),
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

func boolEnv(key string, fallback bool) bool {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "y":
			return true
		case "0", "false", "no", "n":
			return false
		}
	}
	return fallback
}

func parseDuration(key, secondsKey string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			return d
		}
	}
	if raw := strings.TrimSpace(os.Getenv(secondsKey)); raw != "" {
		if val, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return time.Duration(val) * time.Second
		}
	}
	return fallback
}
