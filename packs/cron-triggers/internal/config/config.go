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
	defaultPool           = "cron-triggers"
	defaultQueue          = "cron-triggers"
	defaultSubject        = "job.cron-triggers.*"
	defaultRequestTimeout = 20 * time.Second
	defaultSyncInterval   = 30 * time.Second
	defaultLockTTL        = 2 * time.Minute
	defaultTimezone       = "UTC"
	defaultSchedulerID    = "cron-triggers"
)

type Profile struct {
	Name             string   `json:"name"`
	AllowedWorkflows []string `json:"allowed_workflows"`
	DeniedWorkflows  []string `json:"denied_workflows"`
	DefaultTimezone  string   `json:"default_timezone"`
	AllowSeconds     bool     `json:"allow_seconds"`
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

	SyncInterval   time.Duration
	LockTTL        time.Duration
	SchedulerID    string
	DefaultProfile string
	Profiles       map[string]Profile
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:         envOr("CORDUM_API_KEY", ""),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_CRON_POOL", defaultPool),
		Queue:          envOr("CORDUM_CRON_QUEUE", defaultQueue),
		RequestTimeout: durationEnv("CORDUM_CRON_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      durationEnv("CORDUM_CRON_RESULT_TTL", 0),
		SyncInterval:   durationEnv("CORDUM_CRON_SYNC_INTERVAL", defaultSyncInterval),
		LockTTL:        durationEnv("CORDUM_CRON_LOCK_TTL", defaultLockTTL),
		SchedulerID:    envOr("CORDUM_CRON_SCHEDULER_ID", defaultSchedulerID),
		DefaultProfile: strings.TrimSpace(os.Getenv("CORDUM_CRON_DEFAULT_PROFILE")),
		Profiles:       map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_CRON_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_CRON_MAX_PARALLEL")); raw != "" {
		if val, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(val)
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_CRON_PROFILES")); raw != "" {
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
			Name:             "default",
			AllowedWorkflows: splitList(os.Getenv("CORDUM_CRON_ALLOWED_WORKFLOWS")),
			DeniedWorkflows:  splitList(os.Getenv("CORDUM_CRON_DENIED_WORKFLOWS")),
			DefaultTimezone:  envOr("CORDUM_CRON_DEFAULT_TIMEZONE", defaultTimezone),
			AllowSeconds:     boolEnv("CORDUM_CRON_ALLOW_SECONDS", false),
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
	if strings.TrimSpace(profile.DefaultTimezone) == "" {
		profile.DefaultTimezone = defaultTimezone
	}
	return profile
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

func durationEnv(key string, fallback time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if val, err := time.ParseDuration(raw); err == nil {
			return val
		}
	}
	return fallback
}
