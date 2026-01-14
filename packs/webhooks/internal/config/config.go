package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	defaultGatewayURL = "http://localhost:8081"
	defaultBind       = ":8089"
	defaultMaxBody    = int64(1024 * 1024)
)

type Route struct {
	ID                string   `json:"id"`
	Path              string   `json:"path"`
	Method            string   `json:"method"`
	WorkflowID        string   `json:"workflow_id"`
	OrgID             string   `json:"org_id"`
	TeamID            string   `json:"team_id"`
	Secret            string   `json:"secret"`
	SecretEnv         string   `json:"secret_env"`
	SignatureHeader   string   `json:"signature_header"`
	SignatureType     string   `json:"signature_type"`
	TokenHeader       string   `json:"token_header"`
	IdempotencyHeader string   `json:"idempotency_header"`
	AllowedIPRanges   []string `json:"allowed_ip_ranges"`
	DeniedIPRanges    []string `json:"denied_ip_ranges"`
	MaxBodyBytes      int64    `json:"max_body_bytes"`

	AllowedCIDRs []*net.IPNet `json:"-"`
	DeniedCIDRs  []*net.IPNet `json:"-"`
}

type Config struct {
	GatewayURL  string
	APIKey      string
	BindAddress string
	MaxBody     int64
	TrustProxy  bool
	Routes      []Route
}

func Load() (Config, error) {
	cfg := Config{
		GatewayURL:  envOr("CORDUM_GATEWAY_URL", defaultGatewayURL),
		APIKey:      envOr("CORDUM_API_KEY", ""),
		BindAddress: envOr("CORDUM_WEBHOOKS_BIND", defaultBind),
		MaxBody:     parseInt64("CORDUM_WEBHOOKS_MAX_BODY_BYTES", defaultMaxBody),
		TrustProxy:  boolEnv("CORDUM_WEBHOOKS_TRUST_PROXY", false),
		Routes:      []Route{},
	}

	routesRaw := strings.TrimSpace(os.Getenv("CORDUM_WEBHOOKS_ROUTES"))
	if routesRaw == "" {
		return cfg, fmt.Errorf("CORDUM_WEBHOOKS_ROUTES required")
	}
	if err := json.Unmarshal([]byte(routesRaw), &cfg.Routes); err != nil {
		return cfg, fmt.Errorf("parse routes: %w", err)
	}
	if len(cfg.Routes) == 0 {
		return cfg, fmt.Errorf("at least one webhook route required")
	}
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		normalizeRoute(route, cfg.MaxBody)
		if err := compileCIDRs(route); err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

func normalizeRoute(route *Route, fallbackMaxBody int64) {
	route.Path = strings.TrimSpace(route.Path)
	if route.ID == "" {
		route.ID = route.Path
	}
	if route.Method == "" {
		route.Method = "POST"
	}
	route.Method = strings.ToUpper(strings.TrimSpace(route.Method))
	if route.MaxBodyBytes == 0 {
		route.MaxBodyBytes = fallbackMaxBody
	}
	sigType := strings.ToLower(strings.TrimSpace(route.SignatureType))
	if sigType == "" {
		sigType = "none"
	}
	route.SignatureType = sigType
	if route.TokenHeader == "" {
		route.TokenHeader = "X-Webhook-Token"
	}
	if route.SignatureHeader == "" {
		switch sigType {
		case "hmac_sha256":
			route.SignatureHeader = "X-Hub-Signature-256"
		case "hmac_sha1":
			route.SignatureHeader = "X-Hub-Signature"
		case "token":
			route.SignatureHeader = route.TokenHeader
		}
	}
}

func compileCIDRs(route *Route) error {
	for _, raw := range route.AllowedIPRanges {
		_, cidr, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid allowed cidr %s: %w", raw, err)
		}
		route.AllowedCIDRs = append(route.AllowedCIDRs, cidr)
	}
	for _, raw := range route.DeniedIPRanges {
		_, cidr, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid denied cidr %s: %w", raw, err)
		}
		route.DeniedCIDRs = append(route.DeniedCIDRs, cidr)
	}
	return nil
}

func envOr(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func parseInt64(key string, fallback int64) int64 {
	if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
		if val, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return val
		}
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
