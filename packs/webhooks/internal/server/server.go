package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- needed for legacy webhook signatures (e.g., GitHub X-Hub-Signature).
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/config"
	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/gatewayclient"
)

type Server struct {
	cfg     config.Config
	gateway *gatewayclient.Client
}

func New(cfg config.Config, gateway *gatewayclient.Client) *Server {
	return &Server{cfg: cfg, gateway: gateway}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	for _, route := range s.cfg.Routes {
		route := route
		mux.HandleFunc(route.Path, s.routeHandler(route))
	}
	return mux
}

func (s *Server) routeHandler(route config.Route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != route.Method {
			w.Header().Set("Allow", route.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(route.WorkflowID) == "" {
			http.Error(w, "workflow_id missing", http.StatusBadRequest)
			return
		}

		sourceIP := resolveSourceIP(r, s.cfg.TrustProxy, s.cfg.TrustProxyCIDRs)
		if !ipAllowed(route, sourceIP) {
			http.Error(w, "source ip not allowed", http.StatusForbidden)
			return
		}

		maxBody := route.MaxBodyBytes
		if maxBody <= 0 {
			maxBody = s.cfg.MaxBody
		}
		reader := http.MaxBytesReader(w, r.Body, maxBody)
		defer reader.Close()
		body, err := io.ReadAll(reader)
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}

		secret := resolveSecret(route.Secret, route.SecretEnv)
		if err := verifySignature(route, r, body, secret); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		payload := buildPayload(route, r, sourceIP, body, s.cfg.RedactHeaders, s.cfg.RedactHeaderNames)

		idempotencyKey := ""
		if strings.TrimSpace(route.IdempotencyHeader) != "" {
			idempotencyKey = strings.TrimSpace(r.Header.Get(route.IdempotencyHeader))
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		runID, err := s.gateway.StartRun(ctx, route.WorkflowID, payload, gatewayclient.StartRunOptions{
			OrgID:          route.OrgID,
			TeamID:         route.TeamID,
			IdempotencyKey: idempotencyKey,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]any{
			"ok":     true,
			"run_id": runID,
		})
	}
}

func resolveSourceIP(r *http.Request, trustProxy bool, trustedProxyCIDRs []*net.IPNet) string {
	remoteIP := resolveRemoteIP(r.RemoteAddr)
	if trustProxy {
		if len(trustedProxyCIDRs) > 0 && !ipInCIDRs(remoteIP, trustedProxyCIDRs) {
			return remoteIP
		}
		if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	return remoteIP
}

func resolveRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func ipInCIDRs(ip string, cidrs []*net.IPNet) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func ipAllowed(route config.Route, ip string) bool {
	if ip == "" {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range route.DeniedCIDRs {
		if cidr.Contains(parsed) {
			return false
		}
	}
	if len(route.AllowedCIDRs) == 0 {
		return true
	}
	for _, cidr := range route.AllowedCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func verifySignature(route config.Route, r *http.Request, body []byte, secret string) error {
	switch strings.ToLower(route.SignatureType) {
	case "", "none":
		return nil
	case "token":
		if secret == "" {
			return fmt.Errorf("webhook secret required")
		}
		header := route.SignatureHeader
		if header == "" {
			header = route.TokenHeader
		}
		if header == "" {
			return fmt.Errorf("token header not configured")
		}
		if !secureCompare(strings.TrimSpace(r.Header.Get(header)), secret) {
			return fmt.Errorf("invalid webhook token")
		}
		return nil
	case "hmac_sha256":
		return verifyHMAC(r, body, secret, route.SignatureHeader, sha256.New)
	case "hmac_sha1":
		return verifyHMAC(r, body, secret, route.SignatureHeader, sha1.New)
	default:
		return fmt.Errorf("unsupported signature type: %s", route.SignatureType)
	}
}

func verifyHMAC(r *http.Request, body []byte, secret, header string, hashFn func() hash.Hash) error {
	if secret == "" {
		return fmt.Errorf("webhook secret required")
	}
	if header == "" {
		return fmt.Errorf("signature header required")
	}
	provided := strings.TrimSpace(r.Header.Get(header))
	if provided == "" {
		return fmt.Errorf("signature missing")
	}
	provided = normalizeSignature(provided)
	mac := hmac.New(hashFn, []byte(secret))
	_, _ = mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func normalizeSignature(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "=") {
		parts := strings.SplitN(raw, "=", 2)
		return strings.TrimSpace(parts[1])
	}
	return raw
}

func buildPayload(route config.Route, r *http.Request, sourceIP string, body []byte, redactHeaders bool, redactHeaderNames []string) map[string]any {
	parsedBody := parseBody(body)
	return map[string]any{
		"webhook": map[string]any{
			"id":          route.ID,
			"path":        route.Path,
			"method":      r.Method,
			"headers":     headersToMap(r.Header, redactHeaders, buildSensitiveHeaders(route, redactHeaderNames)),
			"query":       r.URL.Query(),
			"body":        parsedBody,
			"raw_body":    string(body),
			"source_ip":   sourceIP,
			"received_at": time.Now().UTC().Format(time.RFC3339),
		},
	}
}

func parseBody(body []byte) any {
	if len(body) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err == nil {
		return decoded
	}
	return strings.TrimSpace(string(body))
}

func headersToMap(headers http.Header, redact bool, sensitiveHeaders map[string]struct{}) map[string][]string {
	out := map[string][]string{}
	for key, values := range headers {
		if redact && isSensitiveHeader(key, sensitiveHeaders) {
			out[key] = []string{redactedValue}
			continue
		}
		out[key] = values
	}
	return out
}

func isSensitiveHeader(key string, sensitiveHeaders map[string]struct{}) bool {
	_, ok := sensitiveHeaders[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

func buildSensitiveHeaders(route config.Route, extra []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, name := range defaultSensitiveHeaders {
		out[name] = struct{}{}
	}
	if header := strings.TrimSpace(route.SignatureHeader); header != "" {
		out[strings.ToLower(header)] = struct{}{}
	}
	if header := strings.TrimSpace(route.TokenHeader); header != "" {
		out[strings.ToLower(header)] = struct{}{}
	}
	for _, name := range extra {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			out[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	return out
}

func secureCompare(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

const redactedValue = "[redacted]"

var defaultSensitiveHeaders = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"x-webhook-token",
	"x-hub-signature",
	"x-hub-signature-256",
	"x-gitlab-token",
	"x-github-token",
	"x-slack-signature",
	"x-slack-request-timestamp",
}

func resolveSecret(value, envKey string) string {
	envKey = strings.TrimSpace(envKey)
	if envKey != "" {
		if envValue := strings.TrimSpace(os.Getenv(envKey)); envValue != "" {
			return envValue
		}
	}
	return strings.TrimSpace(value)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
