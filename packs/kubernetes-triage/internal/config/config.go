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
	defaultPool           = "kubernetes-triage"
	defaultQueue          = "kubernetes-triage"
	defaultSubject        = "job.kubernetes-triage.*"
	defaultKubectlPath    = "kubectl"
	defaultNamespace      = "default"
	defaultRequestTimeout = 45 * time.Second
	defaultCommandTimeout = 30 * time.Second
)

type Profile struct {
	Name                 string            `json:"name"`
	Kubeconfig           string            `json:"kubeconfig"`
	Context              string            `json:"context"`
	Namespace            string            `json:"namespace"`
	KubectlPath          string            `json:"kubectl_path"`
	AllowedNamespaces    []string          `json:"allowed_namespaces"`
	DeniedNamespaces     []string          `json:"denied_namespaces"`
	AllowActions         []string          `json:"allow_actions"`
	DenyActions          []string          `json:"deny_actions"`
	Headers              map[string]string `json:"headers"`
	Timeout              time.Duration     `json:"-"`
	TimeoutString        string            `json:"timeout"`
	CommandTimeout       time.Duration     `json:"-"`
	CommandTimeoutString string            `json:"command_timeout"`
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
	CommandTimeout time.Duration
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
		Pool:           envOr("CORDUM_K8S_POOL", defaultPool),
		Queue:          envOr("CORDUM_K8S_QUEUE", defaultQueue),
		RequestTimeout: defaultRequestTimeout,
		CommandTimeout: defaultCommandTimeout,
		ResultTTL:      parseDuration("CORDUM_K8S_RESULT_TTL", "CORDUM_K8S_RESULT_TTL_SECONDS", 0),
		DefaultProfile: strings.TrimSpace(os.Getenv("CORDUM_K8S_DEFAULT_PROFILE")),
		Profiles:       map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_K8S_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_K8S_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_K8S_REQUEST_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.RequestTimeout = d
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_K8S_COMMAND_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.CommandTimeout = d
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_K8S_PROFILES")); raw != "" {
		var profiles []Profile
		if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
			return cfg, err
		}
		for _, profile := range profiles {
			profile = normalizeProfile(profile, cfg.CommandTimeout)
			if strings.TrimSpace(profile.Name) == "" {
				continue
			}
			cfg.Profiles[profile.Name] = profile
		}
	}

	if len(cfg.Profiles) == 0 {
		defaultProfile := normalizeProfile(Profile{
			Name:              "default",
			Kubeconfig:        strings.TrimSpace(os.Getenv("CORDUM_K8S_KUBECONFIG")),
			Context:           strings.TrimSpace(os.Getenv("CORDUM_K8S_CONTEXT")),
			Namespace:         envOr("CORDUM_K8S_NAMESPACE", defaultNamespace),
			KubectlPath:       envOr("CORDUM_K8S_KUBECTL_PATH", defaultKubectlPath),
			AllowedNamespaces: splitList(os.Getenv("CORDUM_K8S_ALLOWED_NAMESPACES")),
			DeniedNamespaces:  splitList(os.Getenv("CORDUM_K8S_DENIED_NAMESPACES")),
			AllowActions:      splitList(os.Getenv("CORDUM_K8S_ALLOW_ACTIONS")),
			DenyActions:       splitList(os.Getenv("CORDUM_K8S_DENY_ACTIONS")),
			Headers:           map[string]string{},
		}, cfg.CommandTimeout)
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

func normalizeProfile(profile Profile, defaultCommandTimeout time.Duration) Profile {
	if strings.TrimSpace(profile.Namespace) == "" {
		profile.Namespace = defaultNamespace
	}
	if strings.TrimSpace(profile.KubectlPath) == "" {
		profile.KubectlPath = defaultKubectlPath
	}
	if profile.Headers == nil {
		profile.Headers = map[string]string{}
	}
	if raw := strings.TrimSpace(profile.TimeoutString); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			profile.Timeout = d
		}
	}
	if raw := strings.TrimSpace(profile.CommandTimeoutString); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			profile.CommandTimeout = d
		}
	}
	if profile.CommandTimeout == 0 {
		profile.CommandTimeout = defaultCommandTimeout
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
