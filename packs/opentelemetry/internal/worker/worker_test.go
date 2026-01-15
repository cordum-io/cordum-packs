package worker

import (
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/opentelemetry/internal/config"
)

func TestResolvePath(t *testing.T) {
	params := map[string]any{"trace_id": "abc123"}
	pathValue, cleaned, err := resolvePath("/traces/{trace_id}", params, []string{"trace_id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pathValue != "/traces/abc123" {
		t.Fatalf("unexpected path: %s", pathValue)
	}
	if _, ok := cleaned["trace_id"]; ok {
		t.Fatalf("expected trace_id to be removed")
	}
}

func TestEnforceServicePolicy(t *testing.T) {
	profile := config.Profile{AllowedServices: []string{"api-*"}}
	if err := enforceServicePolicy(profile, "api-gateway"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceServicePolicy(profile, "worker"); err == nil {
		t.Fatalf("expected error for disallowed service")
	}

	profile = config.Profile{DeniedServices: []string{"internal"}}
	if err := enforceServicePolicy(profile, "internal"); err == nil {
		t.Fatalf("expected error for denied service")
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"service": "api"}
	if err := validateParams(params, []string{"service"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(map[string]any{}, []string{"service"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}

func TestResolveSecret(t *testing.T) {
	os.Setenv("OTEL_TEST_TOKEN", "env-token")
	defer os.Unsetenv("OTEL_TEST_TOKEN")

	if got := resolveSecret("raw-token", "OTEL_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
	os.Unsetenv("OTEL_TEST_TOKEN")
	if got := resolveSecret("raw-token", "OTEL_TEST_TOKEN"); got != "raw-token" {
		t.Fatalf("expected raw token, got %q", got)
	}
}
