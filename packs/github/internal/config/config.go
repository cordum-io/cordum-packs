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
	defaultPool           = "github"
	defaultQueue          = "github"
	defaultSubject        = "job.github.*"
	defaultBaseURL        = "https://api.github.com"
	defaultAPIVersion     = "2022-11-28"
	defaultUserAgent      = "cordum-github-worker/0.1.0"
	defaultRequestTimeout = 45 * time.Second
)

type AppAuth struct {
	AppID             string `json:"app_id"`
	AppIDEnv          string `json:"app_id_env"`
	PrivateKey        string `json:"app_private_key"`
	PrivateKeyEnv     string `json:"app_private_key_env"`
	InstallationID    string `json:"app_installation_id"`
	InstallationIDEnv string `json:"app_installation_id_env"`
}

type Profile struct {
	Name          string            `json:"name"`
	BaseURL       string            `json:"base_url"`
	Token         string            `json:"token"`
	TokenEnv      string            `json:"token_env"`
	TokenType     string            `json:"token_type"`
	App           AppAuth           `json:"app"`
	AllowedRepos  []string          `json:"allowed_repos"`
	DeniedRepos   []string          `json:"denied_repos"`
	AllowActions  []string          `json:"allow_actions"`
	DenyActions   []string          `json:"deny_actions"`
	Headers       map[string]string `json:"headers"`
	UserAgent     string            `json:"user_agent"`
	APIVersion    string            `json:"api_version"`
	Timeout       time.Duration     `json:"-"`
	TimeoutString string            `json:"timeout"`
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
		Pool:            envOr("CORDUM_GITHUB_POOL", defaultPool),
		Queue:           envOr("CORDUM_GITHUB_QUEUE", defaultQueue),
		RequestTimeout:  defaultRequestTimeout,
		ResultTTL:       parseDuration("CORDUM_GITHUB_RESULT_TTL", "CORDUM_GITHUB_RESULT_TTL_SECONDS", 0),
		AllowInlineAuth: boolEnv("CORDUM_GITHUB_ALLOW_INLINE_AUTH", false),
		DefaultProfile:  strings.TrimSpace(os.Getenv("CORDUM_GITHUB_DEFAULT_PROFILE")),
		Profiles:        map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_GITHUB_SUBJECTS")); raw != "" {
		parts := splitList(raw)
		cfg.Subjects = parts
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_GITHUB_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_GITHUB_REQUEST_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.RequestTimeout = d
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_GITHUB_PROFILES")); raw != "" {
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
			BaseURL:      envOr("CORDUM_GITHUB_BASE_URL", defaultBaseURL),
			Token:        strings.TrimSpace(os.Getenv("CORDUM_GITHUB_TOKEN")),
			TokenEnv:     strings.TrimSpace(os.Getenv("CORDUM_GITHUB_TOKEN_ENV")),
			TokenType:    strings.TrimSpace(os.Getenv("CORDUM_GITHUB_TOKEN_TYPE")),
			AllowedRepos: splitList(os.Getenv("CORDUM_GITHUB_ALLOWED_REPOS")),
			DeniedRepos:  splitList(os.Getenv("CORDUM_GITHUB_DENIED_REPOS")),
			AllowActions: splitList(os.Getenv("CORDUM_GITHUB_ALLOW_ACTIONS")),
			DenyActions:  splitList(os.Getenv("CORDUM_GITHUB_DENY_ACTIONS")),
			Headers:      map[string]string{},
			UserAgent:    envOr("CORDUM_GITHUB_USER_AGENT", defaultUserAgent),
			APIVersion:   envOr("CORDUM_GITHUB_API_VERSION", defaultAPIVersion),
			App: AppAuth{
				AppID:             strings.TrimSpace(os.Getenv("CORDUM_GITHUB_APP_ID")),
				AppIDEnv:          strings.TrimSpace(os.Getenv("CORDUM_GITHUB_APP_ID_ENV")),
				PrivateKey:        strings.TrimSpace(os.Getenv("CORDUM_GITHUB_APP_PRIVATE_KEY")),
				PrivateKeyEnv:     strings.TrimSpace(os.Getenv("CORDUM_GITHUB_APP_PRIVATE_KEY_ENV")),
				InstallationID:    strings.TrimSpace(os.Getenv("CORDUM_GITHUB_APP_INSTALLATION_ID")),
				InstallationIDEnv: strings.TrimSpace(os.Getenv("CORDUM_GITHUB_APP_INSTALLATION_ID_ENV")),
			},
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
	if strings.TrimSpace(profile.APIVersion) == "" {
		profile.APIVersion = defaultAPIVersion
	}
	if strings.TrimSpace(profile.UserAgent) == "" {
		profile.UserAgent = defaultUserAgent
	}
	if strings.TrimSpace(profile.TokenType) == "" {
		profile.TokenType = "Bearer"
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

func parseDuration(primaryKey, secondsKey string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(primaryKey)); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			return d
		}
	}
	if raw := strings.TrimSpace(os.Getenv(secondsKey)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return fallback
}
