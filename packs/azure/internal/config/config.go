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
	defaultPool           = "azure"
	defaultQueue          = "azure"
	defaultSubject        = "job.azure.*"
	defaultRequestTimeout = 60 * time.Second
)

// Profile holds per-profile Azure configuration.
type Profile struct {
	Name                  string   `json:"name"`
	TenantID              string   `json:"tenant_id"`
	ClientID              string   `json:"client_id"`
	ClientSecretEnv       string   `json:"client_secret_env"`
	SubscriptionID        string   `json:"subscription_id"`
	ResourceGroup         string   `json:"resource_group"`
	UseManagedIdentity    bool     `json:"use_managed_identity"`
	AllowActions          []string `json:"allow_actions"`
	DenyActions           []string `json:"deny_actions"`
	AllowedSubscriptions  []string `json:"allowed_subscriptions"`
	DeniedSubscriptions   []string `json:"denied_subscriptions"`
}

// Config holds all Azure pack configuration.
type Config struct {
	GatewayURL     string
	APIKey         string
	TenantID       string
	NatsURL        string
	RedisURL       string
	Pool           string
	Queue          string
	Subjects       []string
	MaxParallel    int32
	RequestTimeout time.Duration
	ResultTTL      time.Duration

	// Azure-specific
	AzureTenantID      string
	AzureClientID      string
	AzureClientSecret  string
	SubscriptionID     string
	ResourceGroup      string
	AllowActions       []string
	DenyActions        []string

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
		Pool:           envOr("CORDUM_AZURE_POOL", defaultPool),
		Queue:          envOr("CORDUM_AZURE_QUEUE", defaultQueue),
		RequestTimeout: parseDuration("CORDUM_AZURE_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:      parseDuration("CORDUM_AZURE_RESULT_TTL", 0),

		AzureTenantID:  strings.TrimSpace(os.Getenv("AZURE_TENANT_ID")),
		AzureClientID:  strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID")),
		AzureClientSecret: strings.TrimSpace(os.Getenv("AZURE_CLIENT_SECRET")),
		SubscriptionID: strings.TrimSpace(os.Getenv("AZURE_SUBSCRIPTION_ID")),
		ResourceGroup:  strings.TrimSpace(os.Getenv("CORDUM_AZURE_RESOURCE_GROUP")),
		AllowActions:   splitList(os.Getenv("CORDUM_AZURE_ALLOW_ACTIONS")),
		DenyActions:    splitList(os.Getenv("CORDUM_AZURE_DENY_ACTIONS")),

		DefaultProfile: strings.TrimSpace(os.Getenv("CORDUM_AZURE_DEFAULT_PROFILE")),
		Profiles:       map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_AZURE_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_AZURE_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	// Profile loading
	if raw := strings.TrimSpace(os.Getenv("CORDUM_AZURE_PROFILES")); raw != "" {
		var profiles []Profile
		if err := json.Unmarshal([]byte(raw), &profiles); err != nil {
			return cfg, err
		}
		for _, p := range profiles {
			p = normalizeProfile(p, cfg)
			if strings.TrimSpace(p.Name) == "" {
				continue
			}
			cfg.Profiles[p.Name] = p
		}
	}

	// Default profile
	if len(cfg.Profiles) == 0 {
		cfg.Profiles["default"] = normalizeProfile(Profile{
			Name:           "default",
			TenantID:       cfg.AzureTenantID,
			ClientID:       cfg.AzureClientID,
			ClientSecretEnv: "AZURE_CLIENT_SECRET",
			SubscriptionID: cfg.SubscriptionID,
			ResourceGroup:  cfg.ResourceGroup,
			AllowActions:   cfg.AllowActions,
			DenyActions:    cfg.DenyActions,
		}, cfg)
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
	return Profile{Name: "default", SubscriptionID: c.SubscriptionID}
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

// ResolveClientSecret returns the client secret from env.
func (p Profile) ResolveClientSecret() string {
	if p.ClientSecretEnv != "" {
		return strings.TrimSpace(os.Getenv(p.ClientSecretEnv))
	}
	return ""
}

func normalizeProfile(p Profile, cfg Config) Profile {
	if p.SubscriptionID == "" {
		p.SubscriptionID = cfg.SubscriptionID
	}
	if p.ResourceGroup == "" {
		p.ResourceGroup = cfg.ResourceGroup
	}
	return p
}

func matchGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, value)
	}
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
