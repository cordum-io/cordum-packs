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

		sourceIP := resolveSourceIP(r, s.cfg.TrustProxy)
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

		payload := buildPayload(route, r, sourceIP, body)

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

func resolveSourceIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
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
		if strings.TrimSpace(r.Header.Get(header)) != secret {
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

func buildPayload(route config.Route, r *http.Request, sourceIP string, body []byte) map[string]any {
	parsedBody := parseBody(body)
	return map[string]any{
		"webhook": map[string]any{
			"id":          route.ID,
			"path":        route.Path,
			"method":      r.Method,
			"headers":     headersToMap(r.Header),
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

func headersToMap(headers http.Header) map[string][]string {
	out := map[string][]string{}
	for key, values := range headers {
		out[key] = values
	}
	return out
}

func resolveSecret(value, envKey string) string {
	if strings.TrimSpace(envKey) != "" {
		return strings.TrimSpace(os.Getenv(envKey))
	}
	return strings.TrimSpace(value)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
