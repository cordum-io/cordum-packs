package worker

import (
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/vault/internal/config"
)

func TestResolveSecretPathKV2(t *testing.T) {
	path := resolveSecretPath("secret/app", 2, false)
	if path != "/secret/data/app" {
		t.Fatalf("unexpected path: %s", path)
	}
	listPath := resolveSecretPath("secret/app", 2, true)
	if listPath != "/secret/metadata/app" {
		t.Fatalf("unexpected list path: %s", listPath)
	}
}

func TestNormalizePolicyPath(t *testing.T) {
	if got := normalizePolicyPath("secret/data/app"); got != "secret/app" {
		t.Fatalf("unexpected policy path: %s", got)
	}
}

func TestEnforcePathPolicy(t *testing.T) {
	profile := config.Profile{AllowedPaths: []string{"secret/*"}}
	if err := enforcePathPolicy(profile, "secret/app"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforcePathPolicy(profile, "other/app"); err == nil {
		t.Fatalf("expected error for disallowed path")
	}

	profile = config.Profile{DeniedPaths: []string{"secret/deny"}}
	if err := enforcePathPolicy(profile, "secret/deny"); err == nil {
		t.Fatalf("expected error for denied path")
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"path": "secret/app"}
	if err := validateParams(params, []string{"path|secret"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(map[string]any{}, []string{"path"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}

func TestResolveSecretPrefersEnv(t *testing.T) {
	os.Setenv("VAULT_TEST_TOKEN", "env-token")
	defer os.Unsetenv("VAULT_TEST_TOKEN")

	if got := resolveSecret("raw-token", "VAULT_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
}
