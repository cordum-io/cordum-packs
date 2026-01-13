package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayURL      = "http://localhost:8081"
	defaultNatsURL         = "nats://localhost:4222"
	defaultRedisURL        = "redis://localhost:6379"
	defaultPool            = "mcp-client"
	defaultQueue           = "mcp-client"
	defaultJobTopic        = "job.mcp-client.call"
	defaultPackID          = "mcp-client"
	defaultClientName      = "cordum-mcp-client"
	defaultClientVersion   = "0.1.0"
	defaultCallTimeout     = 60 * time.Second
	defaultProtocolVersion = "2025-11-25"
)

type OAuthConfig struct {
	TokenURL        string   `json:"token_url"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	ClientSecretEnv string   `json:"client_secret_env"`
	Scopes          []string `json:"scopes"`
	Audience        string   `json:"audience"`
}

type AuthConfig struct {
	APIKey           string       `json:"api_key"`
	APIKeyEnv        string       `json:"api_key_env"`
	APIKeyHeader     string       `json:"api_key_header"`
	Bearer           string       `json:"bearer"`
	BearerEnv        string       `json:"bearer_env"`
	BasicUsername    string       `json:"basic_username"`
	BasicPassword    string       `json:"basic_password"`
	BasicPasswordEnv string       `json:"basic_password_env"`
	OAuth            *OAuthConfig `json:"oauth"`
}

type ServerConfig struct {
	Name            string            `json:"name"`
	Transport       string            `json:"transport"`
	Command         string            `json:"command"`
	Args            []string          `json:"args"`
	URL             string            `json:"url"`
	Env             map[string]string `json:"env"`
	Headers         map[string]string `json:"headers"`
	AllowTools      []string          `json:"allow_tools"`
	DenyTools       []string          `json:"deny_tools"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	ProtocolVersion string            `json:"protocol_version"`
	Auth            AuthConfig        `json:"auth"`
}

type Config struct {
	GatewayURL        string
	APIKey            string
	NatsURL           string
	RedisURL          string
	Pool              string
	Subjects          []string
	Queue             string
	JobTopic          string
	PackID            string
	ClientName        string
	ClientVersion     string
	CallTimeout       time.Duration
	ProtocolVersion   string
	MaxParallel       int32
	AllowInlineServer bool
	AllowInlineAuth   bool
	Servers           map[string]ServerConfig
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL:        envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:            envOr("CORDUM_API_KEY", ""),
		NatsURL:           envOr("CORDUM_NATS_URL", defaultNatsURL),
		RedisURL:          envOr("CORDUM_REDIS_URL", defaultRedisURL),
		Pool:              envOr("CORDUM_MCP_CLIENT_POOL", defaultPool),
		Queue:             envOr("CORDUM_MCP_CLIENT_QUEUE", defaultQueue),
		JobTopic:          envOr("CORDUM_MCP_CLIENT_JOB_TOPIC", defaultJobTopic),
		PackID:            envOr("CORDUM_MCP_CLIENT_PACK_ID", defaultPackID),
		ClientName:        envOr("CORDUM_MCP_CLIENT_NAME", defaultClientName),
		ClientVersion:     envOr("CORDUM_MCP_CLIENT_VERSION", defaultClientVersion),
		ProtocolVersion:   envOr("CORDUM_MCP_CLIENT_PROTOCOL_VERSION", defaultProtocolVersion),
		CallTimeout:       defaultCallTimeout,
		AllowInlineServer: boolEnv("CORDUM_MCP_CLIENT_ALLOW_INLINE_SERVER", false),
		AllowInlineAuth:   boolEnv("CORDUM_MCP_CLIENT_ALLOW_INLINE_AUTH", false),
		Servers:           map[string]ServerConfig{},
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_MCP_CLIENT_SUBJECTS")); raw != "" {
		parts := strings.Split(raw, ",")
		for i, part := range parts {
			parts[i] = strings.TrimSpace(part)
		}
		cfg.Subjects = parts
	} else {
		cfg.Subjects = []string{"job.mcp-client.*"}
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_MCP_CLIENT_CALL_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.CallTimeout = d
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_MCP_CLIENT_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_MCP_CLIENT_SERVERS")); raw != "" {
		var servers []ServerConfig
		if err := json.Unmarshal([]byte(raw), &servers); err != nil {
			return cfg, err
		}
		for _, server := range servers {
			if strings.TrimSpace(server.Name) == "" {
				continue
			}
			cfg.Servers[server.Name] = server
		}
	}

	return cfg, nil
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
