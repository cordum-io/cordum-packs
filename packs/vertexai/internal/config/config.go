package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL       = "http://localhost:8081"
	defaultNatsURL          = "nats://localhost:4222"
	defaultRedisURL         = "redis://localhost:6379"
	defaultPool             = "vertexai"
	defaultQueue            = "vertexai"
	defaultSubject          = "job.vertexai.*"
	defaultLocation         = "us-central1"
	defaultRequestTimeout   = 120 * time.Second
	defaultUserAgent        = "cordum-vertexai-worker/0.1.0"
	defaultMaxTokensPerCall = 32768
)

// Profile holds per-profile Vertex AI configuration.
type Profile struct {
	Name                      string   `json:"name"`
	ProjectID                 string   `json:"project_id"`
	Location                  string   `json:"location"`
	CredentialsFile           string   `json:"credentials_file"`
	CredentialsFileEnv        string   `json:"credentials_file_env"`
	ImpersonateServiceAccount string   `json:"impersonate_sa"`
	AllowedModels             []string `json:"allowed_models"`
	DeniedModels              []string `json:"denied_models"`
	MaxTokensPerRequest       int      `json:"max_tokens_per_request"`
}

// Config holds all Vertex AI pack configuration.
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

	DefaultProjectID    string
	DefaultLocation     string
	AllowedModels       []string
	DeniedModels        []string
	MaxTokensPerRequest int
	UserAgent           string

	DefaultProfile string
	Profiles       map[string]Profile
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:          envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:              strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:            envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:             envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:            envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:                envOr("CORDUM_VERTEXAI_POOL", defaultPool),
		Queue:               envOr("CORDUM_VERTEXAI_QUEUE", defaultQueue),
		RequestTimeout:      parseDuration("CORDUM_VERTEXAI_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:           parseDuration("CORDUM_VERTEXAI_RESULT_TTL", 0),
		DefaultProjectID:    envOr("GCP_PROJECT_ID", envOr("GOOGLE_CLOUD_PROJECT", strings.TrimSpace(os.Getenv("GCLOUD_PROJECT")))),
		DefaultLocation:     envOr("VERTEX_LOCATION", envOr("CORDUM_VERTEXAI_LOCATION", defaultLocation)),
		AllowedModels:       splitList(os.Getenv("CORDUM_VERTEXAI_ALLOWED_MODELS")),
		DeniedModels:        splitList(os.Getenv("CORDUM_VERTEXAI_DENIED_MODELS")),
		MaxTokensPerRequest: intEnv("CORDUM_VERTEXAI_MAX_TOKENS_PER_REQUEST", defaultMaxTokensPerCall),
		UserAgent:           envOr("CORDUM_VERTEXAI_USER_AGENT", defaultUserAgent),
		DefaultProfile:      strings.TrimSpace(os.Getenv("CORDUM_VERTEXAI_DEFAULT_PROFILE")),
		Profiles:            map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_VERTEXAI_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_VERTEXAI_MAX_PARALLEL")); raw != "" {
		if value, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(value)
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_VERTEXAI_PROFILES")); raw != "" {
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

	if len(cfg.Profiles) == 0 {
		defaultProfile := normalizeProfile(Profile{
			Name:                      "default",
			ProjectID:                 cfg.DefaultProjectID,
			Location:                  cfg.DefaultLocation,
			CredentialsFileEnv:        "GOOGLE_APPLICATION_CREDENTIALS",
			ImpersonateServiceAccount: strings.TrimSpace(os.Getenv("CORDUM_VERTEXAI_IMPERSONATE_SERVICE_ACCOUNT")),
			AllowedModels:             cfg.AllowedModels,
			DeniedModels:              cfg.DeniedModels,
			MaxTokensPerRequest:       cfg.MaxTokensPerRequest,
		}, cfg)
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

// ResolveProfile returns the named profile or the default profile.
func (c Config) ResolveProfile(name string) Profile {
	if trimmed := strings.TrimSpace(name); trimmed != "" {
		if profile, ok := c.Profiles[trimmed]; ok {
			return profile
		}
	}
	if profile, ok := c.Profiles[c.DefaultProfile]; ok {
		return profile
	}
	return normalizeProfile(Profile{Name: "default"}, c)
}

// ResolveProjectID returns the effective project ID.
func (p Profile) ResolveProjectID(override, fallback string) string {
	return firstNonEmpty(strings.TrimSpace(override), strings.TrimSpace(p.ProjectID), strings.TrimSpace(fallback))
}

// ResolveLocation returns the effective location.
func (p Profile) ResolveLocation(override, fallback string) string {
	return firstNonEmpty(strings.TrimSpace(override), strings.TrimSpace(p.Location), strings.TrimSpace(fallback), defaultLocation)
}

// ResolveCredentialsFile returns the effective credentials file path.
func (p Profile) ResolveCredentialsFile() string {
	if trimmed := strings.TrimSpace(p.CredentialsFile); trimmed != "" {
		return filepath.Clean(trimmed)
	}
	if trimmed := strings.TrimSpace(p.CredentialsFileEnv); trimmed != "" {
		if value := strings.TrimSpace(os.Getenv(trimmed)); value != "" {
			return filepath.Clean(value)
		}
	}
	return ""
}

// IsModelAllowed checks whether a model is permitted by the profile.
func (p Profile) IsModelAllowed(model string) bool {
	model = strings.TrimSpace(model)
	if model == "" {
		return false
	}
	for _, denied := range p.DeniedModels {
		if matchGlob(denied, model) {
			return false
		}
	}
	if len(p.AllowedModels) == 0 {
		return true
	}
	for _, allowed := range p.AllowedModels {
		if matchGlob(allowed, model) {
			return true
		}
	}
	return false
}

// ResolveMaxTokens returns the configured max token limit.
func (p Profile) ResolveMaxTokens(fallback int) int {
	if p.MaxTokensPerRequest > 0 {
		return p.MaxTokensPerRequest
	}
	if fallback > 0 {
		return fallback
	}
	return defaultMaxTokensPerCall
}

func normalizeProfile(profile Profile, cfg Config) Profile {
	if strings.TrimSpace(profile.ProjectID) == "" {
		profile.ProjectID = cfg.DefaultProjectID
	}
	if strings.TrimSpace(profile.Location) == "" {
		profile.Location = cfg.DefaultLocation
	}
	if len(profile.AllowedModels) == 0 {
		profile.AllowedModels = append([]string(nil), cfg.AllowedModels...)
	}
	if len(profile.DeniedModels) == 0 {
		profile.DeniedModels = append([]string(nil), cfg.DeniedModels...)
	}
	if profile.MaxTokensPerRequest <= 0 {
		profile.MaxTokensPerRequest = cfg.MaxTokensPerRequest
	}
	return profile
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
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
	prefix, suffix := parts[0], parts[1]
	return strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) && strings.HasSuffix(strings.ToLower(value), strings.ToLower(suffix))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
