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
	defaultPool           = "aws"
	defaultQueue          = "aws"
	defaultSubject        = "job.aws.*"
	defaultRegion         = "us-east-1"
	defaultRequestTimeout = 60 * time.Second
	defaultUserAgent      = "cordum-aws-worker/0.1.0"
)

// Profile holds per-profile AWS configuration for multi-account setups.
type Profile struct {
	Name               string   `json:"name"`
	Region             string   `json:"region"`
	AccessKeyID        string   `json:"access_key_id"`
	AccessKeyIDEnv     string   `json:"access_key_id_env"`
	SecretAccessKey    string   `json:"secret_access_key"`
	SecretAccessKeyEnv string   `json:"secret_access_key_env"`
	SessionTokenEnv    string   `json:"session_token_env"`
	RoleARN            string   `json:"role_arn"`
	ExternalID         string   `json:"external_id"`
	AllowActions       []string `json:"allow_actions"`
	DenyActions        []string `json:"deny_actions"`
	AllowedResources   []string `json:"allowed_resources"`
	DeniedResources    []string `json:"denied_resources"`
}

// Config holds all AWS pack configuration.
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

	// AWS-specific
	DefaultRegion    string
	AllowActions     []string
	DenyActions      []string
	AllowedResources []string
	DeniedResources  []string
	UserAgent        string

	// Inline auth
	AllowInlineAuth    bool
	AllowInlineSecrets bool

	// Profiles
	DefaultProfile string
	Profiles       map[string]Profile
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:     envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:         strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:       envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:        envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:       envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:           envOr("CORDUM_AWS_POOL", defaultPool),
		Queue:          envOr("CORDUM_AWS_QUEUE", defaultQueue),
		RequestTimeout: parseDuration("CORDUM_AWS_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      parseDuration("CORDUM_AWS_RESULT_TTL", 0),

		DefaultRegion:    envOr("AWS_REGION", envOr("AWS_DEFAULT_REGION", defaultRegion)),
		AllowActions:     splitList(os.Getenv("CORDUM_AWS_ALLOW_ACTIONS")),
		DenyActions:      splitList(os.Getenv("CORDUM_AWS_DENY_ACTIONS")),
		AllowedResources: splitList(os.Getenv("CORDUM_AWS_ALLOWED_RESOURCES")),
		DeniedResources:  splitList(os.Getenv("CORDUM_AWS_DENIED_RESOURCES")),
		UserAgent:        envOr("CORDUM_AWS_USER_AGENT", defaultUserAgent),

		AllowInlineAuth:    boolEnv("CORDUM_AWS_ALLOW_INLINE_AUTH", false),
		AllowInlineSecrets: boolEnv("CORDUM_AWS_ALLOW_INLINE_SECRETS", false),
		DefaultProfile:     strings.TrimSpace(os.Getenv("CORDUM_AWS_DEFAULT_PROFILE")),
		Profiles:           map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_AWS_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_AWS_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	// Profile loading from JSON env var
	if raw := strings.TrimSpace(os.Getenv("CORDUM_AWS_PROFILES")); raw != "" {
		var profiles []Profile
		if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
			return cfg, err
		}
		for _, profile := range profiles {
			profile = normalizeProfile(profile, cfg)
			if strings.TrimSpace(profile.Name) == "" {
				continue
			}
			cfg.Profiles[profile.Name] = profile
		}
	}

	// Default profile from env vars
	if len(cfg.Profiles) == 0 {
		defaultProfile := normalizeProfile(Profile{
			Name:               "default",
			Region:             cfg.DefaultRegion,
			AccessKeyIDEnv:     "AWS_ACCESS_KEY_ID",
			SecretAccessKeyEnv: "AWS_SECRET_ACCESS_KEY",
			SessionTokenEnv:    "AWS_SESSION_TOKEN",
			RoleARN:            strings.TrimSpace(os.Getenv("CORDUM_AWS_ROLE_ARN")),
			ExternalID:         strings.TrimSpace(os.Getenv("CORDUM_AWS_EXTERNAL_ID")),
			AllowActions:       cfg.AllowActions,
			DenyActions:        cfg.DenyActions,
			AllowedResources:   cfg.AllowedResources,
			DeniedResources:    cfg.DeniedResources,
		}, cfg)
		cfg.Profiles[defaultProfile.Name] = defaultProfile
	}

	// Resolve default profile
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

// ResolveProfile returns the named profile or the default.
func (c Config) ResolveProfile(name string) Profile {
	if name != "" {
		if p, ok := c.Profiles[name]; ok {
			return p
		}
	}
	if p, ok := c.Profiles[c.DefaultProfile]; ok {
		return p
	}
	return Profile{Name: "default", Region: c.DefaultRegion}
}

// IsActionAllowed checks whether an action is permitted by the profile.
func (p Profile) IsActionAllowed(action string) bool {
	if len(p.DenyActions) > 0 {
		for _, denied := range p.DenyActions {
			if matchGlob(denied, action) {
				return false
			}
		}
	}
	if len(p.AllowActions) > 0 {
		for _, allowed := range p.AllowActions {
			if matchGlob(allowed, action) {
				return true
			}
		}
		return false
	}
	return true
}

// IsResourceAllowed checks whether a resource ARN is permitted by the profile.
func (p Profile) IsResourceAllowed(arn string) bool {
	if arn == "" {
		return true
	}
	if len(p.DeniedResources) > 0 {
		for _, denied := range p.DeniedResources {
			if matchGlob(denied, arn) {
				return false
			}
		}
	}
	if len(p.AllowedResources) > 0 {
		for _, allowed := range p.AllowedResources {
			if matchGlob(allowed, arn) {
				return true
			}
		}
		return false
	}
	return true
}

// ResolveAccessKeyID returns the effective access key ID.
func (p Profile) ResolveAccessKeyID() string {
	if p.AccessKeyID != "" {
		return p.AccessKeyID
	}
	if p.AccessKeyIDEnv != "" {
		return strings.TrimSpace(os.Getenv(p.AccessKeyIDEnv))
	}
	return ""
}

// ResolveSecretAccessKey returns the effective secret access key.
func (p Profile) ResolveSecretAccessKey() string {
	if p.SecretAccessKey != "" {
		return p.SecretAccessKey
	}
	if p.SecretAccessKeyEnv != "" {
		return strings.TrimSpace(os.Getenv(p.SecretAccessKeyEnv))
	}
	return ""
}

// ResolveSessionToken returns the session token if set.
func (p Profile) ResolveSessionToken() string {
	if p.SessionTokenEnv != "" {
		return strings.TrimSpace(os.Getenv(p.SessionTokenEnv))
	}
	return ""
}

func normalizeProfile(p Profile, cfg Config) Profile {
	if p.Region == "" {
		p.Region = cfg.DefaultRegion
	}
	return p
}

// matchGlob performs simple glob matching (only * wildcard).
func matchGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, value)
	}
	// Split on * and check prefix/suffix
	parts := strings.SplitN(pattern, "*", 2)
	if len(parts) != 2 {
		return strings.EqualFold(pattern, value)
	}
	prefix := strings.ToLower(parts[0])
	suffix := strings.ToLower(parts[1])
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, prefix) && strings.HasSuffix(lower, suffix)
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
