package bridge

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// validateUnsignedTransport confines the CAP runtime's explicit legacy mode to
// disposable local development. It does not implement CAP-PRODUCTION admission.
func validateUnsignedTransport(cfg Config) error {
	if !cfg.AllowUnsigned {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(os.Getenv("CORDUM_ENV"))) != "development" {
		return fmt.Errorf("unsigned CAP transport requires CORDUM_ENV=development")
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_PRODUCTION")); raw != "" {
		production, err := strconv.ParseBool(raw)
		if err != nil || production {
			return fmt.Errorf("unsigned CAP transport is incompatible with CORDUM_PRODUCTION")
		}
	}
	profile := strings.ToLower(strings.TrimSpace(os.Getenv("CORDUM_CAP_PROFILE")))
	if profile != "" && profile != "compat" {
		return fmt.Errorf("unsigned CAP transport requires CORDUM_CAP_PROFILE=compat")
	}
	for _, endpoint := range []struct{ name, address string }{
		{"gateway", cfg.GatewayURL}, {"NATS", cfg.NatsURL}, {"Redis", cfg.RedisURL},
	} {
		u, err := url.Parse(endpoint.address)
		if err != nil || u.Scheme == "" || u.Hostname() == "" {
			return fmt.Errorf("unsigned CAP transport requires a loopback %s URL", endpoint.name)
		}
		host := u.Hostname()
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("unsigned CAP transport requires a loopback %s URL", endpoint.name)
		}
	}
	return nil
}
