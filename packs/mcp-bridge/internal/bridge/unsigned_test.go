package bridge

import (
	"strings"
	"testing"
)

func unsignedTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{GatewayURL: "http://127.0.0.1:8081", NatsURL: "nats://127.0.0.1:4222", RedisURL: "redis://127.0.0.1:6379", AllowUnsigned: true}
}

func TestUnsignedOptInDefaultsOff(t *testing.T) {
	if (Config{}).AllowUnsigned {
		t.Fatal("unsigned legacy transport must be disabled by default")
	}
}

func TestUnsignedOptInRejectsUnsafeEnvironmentBeforeConnecting(t *testing.T) {
	cases := []struct{ name, mode, profile, production string }{
		{"unset environment", "", "compat", ""},
		{"production environment", "production", "compat", ""},
		{"production boolean", "development", "compat", "true"},
		{"production number", "development", "compat", "1"},
		{"production profile", "development", "production", ""},
		{"unknown profile", "development", "prod", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CORDUM_ENV", tc.mode)
			t.Setenv("CORDUM_CAP_PROFILE", tc.profile)
			t.Setenv("CORDUM_PRODUCTION", tc.production)
			_, err := New(unsignedTestConfig(t))
			if err == nil || !strings.Contains(err.Error(), "unsigned") {
				t.Fatalf("expected unsigned transport configuration rejection before I/O, got %v", err)
			}
		})
	}
}

func TestUnsignedOptInRejectsRemoteEndpointsBeforeConnecting(t *testing.T) {
	t.Setenv("CORDUM_ENV", "development")
	t.Setenv("CORDUM_CAP_PROFILE", "compat")
	t.Setenv("CORDUM_PRODUCTION", "")
	for _, field := range []string{"gateway", "NATS", "Redis"} {
		t.Run(field, func(t *testing.T) {
			cfg := unsignedTestConfig(t)
			switch field {
			case "gateway":
				cfg.GatewayURL = "http://192.0.2.1:8081"
			case "NATS":
				cfg.NatsURL = "nats://192.0.2.1:4222"
			case "Redis":
				cfg.RedisURL = "redis://192.0.2.1:6379"
			}
			_, err := New(cfg)
			if err == nil || !strings.Contains(err.Error(), "unsigned") || !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("expected unsigned non-loopback rejection before I/O, got %v", err)
			}
		})
	}
}

func TestUnsignedOptInAcceptsOnlyLocalDevelopment(t *testing.T) {
	t.Setenv("CORDUM_ENV", "development")
	t.Setenv("CORDUM_CAP_PROFILE", "compat")
	t.Setenv("CORDUM_PRODUCTION", "false")
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "localhost", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			cfg := unsignedTestConfig(t)
			cfg.GatewayURL = "https://" + host + ":8081"
			cfg.NatsURL = "nats://user:password@" + host + ":4222"
			cfg.RedisURL = "rediss://:password@" + host + ":6379/0"
			if err := validateUnsignedTransport(cfg); err != nil {
				t.Fatalf("local development endpoints rejected: %v", err)
			}
		})
	}
}

func TestUnsignedOptInRejectsMalformedAndDeceptiveURLs(t *testing.T) {
	t.Setenv("CORDUM_ENV", "development")
	t.Setenv("CORDUM_CAP_PROFILE", "compat")
	t.Setenv("CORDUM_PRODUCTION", "")
	for _, address := range []string{"127.0.0.1:8081", "http://localhost.example.invalid", "http://127.0.0.1@example.invalid", "http://%zz", "http:///missing-host"} {
		t.Run(address, func(t *testing.T) {
			cfg := unsignedTestConfig(t)
			cfg.GatewayURL = address
			if err := validateUnsignedTransport(cfg); err == nil {
				t.Fatal("malformed or non-loopback URL accepted")
			}
		})
	}
}
