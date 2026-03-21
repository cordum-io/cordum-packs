package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL     = "http://localhost:8081"
	defaultNatsURL        = "nats://localhost:4222"
	defaultRedisURL       = "redis://localhost:6379"
	defaultPool           = "zapier"
	defaultQueue          = "zapier"
	defaultSubject        = "job.zapier.*"
	defaultRequestTimeout = 120 * time.Second
	defaultNLABaseURL     = "https://actions.zapier.com/api/v2"
)

// Config holds all Zapier pack configuration.
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

	NLABaseURL      string
	NLAAPIKey       string
	WebhookURLs     map[string]string
	AllowedActions  []string
	DeniedActions   []string
	AllowedWebhooks []string
	DeniedWebhooks  []string
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:      envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:          strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:        envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:         envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:        envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:            envOr("CORDUM_ZAPIER_POOL", defaultPool),
		Queue:           envOr("CORDUM_ZAPIER_QUEUE", defaultQueue),
		RequestTimeout:  parseDuration("CORDUM_ZAPIER_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:       parseDuration("CORDUM_ZAPIER_RESULT_TTL", 0),
		NLABaseURL:      envOr("ZAPIER_NLA_BASE_URL", envOr("CORDUM_ZAPIER_NLA_BASE_URL", envOr("NLA_BASE_URL", defaultNLABaseURL))),
		NLAAPIKey:       envOr("ZAPIER_NLA_API_KEY", strings.TrimSpace(os.Getenv("CORDUM_ZAPIER_NLA_API_KEY"))),
		WebhookURLs:     map[string]string{},
		AllowedActions:  splitList(envOr("CORDUM_ZAPIER_ALLOWED_ACTIONS", os.Getenv("ZAPIER_ALLOWED_ACTIONS"))),
		DeniedActions:   splitList(envOr("CORDUM_ZAPIER_DENIED_ACTIONS", os.Getenv("ZAPIER_DENIED_ACTIONS"))),
		AllowedWebhooks: splitList(envOr("CORDUM_ZAPIER_ALLOWED_WEBHOOKS", os.Getenv("ZAPIER_ALLOWED_WEBHOOKS"))),
		DeniedWebhooks:  splitList(envOr("CORDUM_ZAPIER_DENIED_WEBHOOKS", os.Getenv("ZAPIER_DENIED_WEBHOOKS"))),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_ZAPIER_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_ZAPIER_MAX_PARALLEL")); raw != "" {
		if value, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(value)
		}
	}
	if raw := strings.TrimSpace(firstNonEmpty(os.Getenv("CORDUM_ZAPIER_WEBHOOK_URLS"), os.Getenv("ZAPIER_WEBHOOK_URLS"))); raw != "" {
		var mapping map[string]string
		if err := json.Unmarshal([]byte(raw), &mapping); err != nil {
			return cfg, fmt.Errorf("parse webhook urls: %w", err)
		}
		normalized, err := normalizeWebhookURLs(mapping)
		if err != nil {
			return cfg, err
		}
		cfg.WebhookURLs = normalized
	}
	return cfg, nil
}

// HasNLA reports whether AI Actions credentials are configured.
func (c Config) HasNLA() bool {
	return strings.TrimSpace(c.NLAAPIKey) != ""
}

// ResolveWebhookURL resolves a configured alias to its target URL.
func (c Config) ResolveWebhookURL(name string) (string, bool) {
	value, ok := c.WebhookURLs[normalizeAlias(name)]
	return value, ok
}

// IsActionAllowed checks action allow/deny rules.
func (c Config) IsActionAllowed(actionID string) bool {
	actionID = strings.TrimSpace(actionID)
	if actionID == "" {
		return len(c.AllowedActions) == 0 && len(c.DeniedActions) == 0
	}
	for _, denied := range c.DeniedActions {
		if matchGlob(denied, actionID) {
			return false
		}
	}
	if len(c.AllowedActions) == 0 {
		return true
	}
	for _, allowed := range c.AllowedActions {
		if matchGlob(allowed, actionID) {
			return true
		}
	}
	return false
}

// IsWebhookAllowed checks webhook alias allow/deny rules.
func (c Config) IsWebhookAllowed(name string) bool {
	alias := normalizeAlias(name)
	if alias == "" {
		return false
	}
	for _, denied := range c.DeniedWebhooks {
		if matchGlob(denied, alias) {
			return false
		}
	}
	if len(c.AllowedWebhooks) == 0 {
		return true
	}
	for _, allowed := range c.AllowedWebhooks {
		if matchGlob(allowed, alias) {
			return true
		}
	}
	return false
}

func normalizeWebhookURLs(mapping map[string]string) (map[string]string, error) {
	normalized := make(map[string]string, len(mapping))
	for key, value := range mapping {
		alias := normalizeAlias(key)
		if alias == "" {
			continue
		}
		normalizedURL, err := normalizeURL(value)
		if err != nil {
			return nil, fmt.Errorf("webhook %q: %w", key, err)
		}
		normalized[alias] = normalizedURL
	}
	return normalized, nil
}

func normalizeURL(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("url required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("url host required")
	}
	return parsed.String(), nil
}

func normalizeAlias(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

func parseDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func splitList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		candidate := strings.TrimSpace(part)
		if candidate != "" {
			out = append(out, candidate)
		}
	}
	return out
}

func matchGlob(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" {
		return false
	}
	if pattern == value {
		return true
	}
	ok, err := path.Match(pattern, value)
	if err == nil && ok {
		return true
	}
	return pattern == "*"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
