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
	defaultGatewayURL     = "http://localhost:8081"
	defaultNatsURL        = "nats://localhost:4222"
	defaultRedisURL       = "redis://localhost:6379"
	defaultPool           = "gcp"
	defaultQueue          = "gcp"
	defaultSubject        = "job.gcp.*"
	defaultLocation       = "global"
	defaultRequestTimeout = 60 * time.Second
	defaultUserAgent      = "cordum-gcp-worker/0.1.0"
)

// Profile holds per-profile GCP configuration for multi-project setups.
type Profile struct {
	Name                      string   `json:"name"`
	ProjectID                 string   `json:"project_id"`
	Location                  string   `json:"location"`
	CredentialsFile           string   `json:"credentials_file"`
	CredentialsFileEnv        string   `json:"credentials_file_env"`
	ImpersonateServiceAccount string   `json:"impersonate_sa"`
	AllowActions              []string `json:"allow_actions"`
	DenyActions               []string `json:"deny_actions"`
	AllowedProjects           []string `json:"allowed_projects"`
	DeniedProjects            []string `json:"denied_projects"`
}

// Config holds all GCP pack configuration.
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

	DefaultProjectID string
	DefaultLocation  string
	AllowActions     []string
	DenyActions      []string
	AllowedProjects  []string
	DeniedProjects   []string
	UserAgent        string

	DefaultProfile string
	Profiles       map[string]Profile
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		GatewayURL:       envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:           strings.TrimSpace(os.Getenv("CORDUM_API_KEY")),
		TenantID:         envOr("CORDUM_TENANT_ID", "default"),
		NatsURL:          envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:         envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:             envOr("CORDUM_GCP_POOL", defaultPool),
		Queue:            envOr("CORDUM_GCP_QUEUE", defaultQueue),
		RequestTimeout:   parseDuration("CORDUM_GCP_REQUEST_TIMEOUT", defaultRequestTimeout),
		ResultTTL:        parseDuration("CORDUM_GCP_RESULT_TTL", 0),
		DefaultProjectID: envOr("GCP_PROJECT_ID", envOr("GOOGLE_CLOUD_PROJECT", strings.TrimSpace(os.Getenv("GCLOUD_PROJECT")))),
		DefaultLocation:  envOr("CORDUM_GCP_DEFAULT_LOCATION", defaultLocation),
		AllowActions:     splitList(os.Getenv("CORDUM_GCP_ALLOW_ACTIONS")),
		DenyActions:      splitList(os.Getenv("CORDUM_GCP_DENY_ACTIONS")),
		AllowedProjects:  splitList(os.Getenv("CORDUM_GCP_ALLOWED_PROJECTS")),
		DeniedProjects:   splitList(os.Getenv("CORDUM_GCP_DENIED_PROJECTS")),
		UserAgent:        envOr("CORDUM_GCP_USER_AGENT", defaultUserAgent),
		DefaultProfile:   strings.TrimSpace(os.Getenv("CORDUM_GCP_DEFAULT_PROFILE")),
		Profiles:         map[string]Profile{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_GCP_SUBJECTS")); raw != "" {
		cfg.Subjects = splitList(raw)
	} else {
		cfg.Subjects = []string{defaultSubject}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_GCP_MAX_PARALLEL")); raw != "" {
		if value, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(value)
		}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_GCP_PROFILES")); raw != "" {
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
			ImpersonateServiceAccount: strings.TrimSpace(os.Getenv("CORDUM_GCP_IMPERSONATE_SERVICE_ACCOUNT")),
			AllowActions:              cfg.AllowActions,
			DenyActions:               cfg.DenyActions,
			AllowedProjects:           cfg.AllowedProjects,
			DeniedProjects:            cfg.DeniedProjects,
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

// ResolveProfile returns the named profile or the default.
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

// IsActionAllowed checks whether an action is permitted by the profile.
func (p Profile) IsActionAllowed(action string) bool {
	for _, denied := range p.DenyActions {
		if matchGlob(denied, action) {
			return false
		}
	}
	if len(p.AllowActions) == 0 {
		return true
	}
	for _, allowed := range p.AllowActions {
		if matchGlob(allowed, action) {
			return true
		}
	}
	return false
}

// IsProjectAllowed checks whether a project is permitted by the profile.
func (p Profile) IsProjectAllowed(projectID string) bool {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return false
	}
	for _, denied := range p.DeniedProjects {
		if matchGlob(denied, projectID) {
			return false
		}
	}
	if len(p.AllowedProjects) == 0 {
		return true
	}
	for _, allowed := range p.AllowedProjects {
		if matchGlob(allowed, projectID) {
			return true
		}
	}
	return false
}

func normalizeProfile(profile Profile, cfg Config) Profile {
	if strings.TrimSpace(profile.ProjectID) == "" {
		profile.ProjectID = cfg.DefaultProjectID
	}
	if strings.TrimSpace(profile.Location) == "" {
		profile.Location = cfg.DefaultLocation
	}
	if len(profile.AllowActions) == 0 {
		profile.AllowActions = append([]string(nil), cfg.AllowActions...)
	}
	if len(profile.DenyActions) == 0 {
		profile.DenyActions = append([]string(nil), cfg.DenyActions...)
	}
	if len(profile.AllowedProjects) == 0 {
		profile.AllowedProjects = append([]string(nil), cfg.AllowedProjects...)
	}
	if len(profile.DeniedProjects) == 0 {
		profile.DeniedProjects = append([]string(nil), cfg.DeniedProjects...)
	}
	return profile
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
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
