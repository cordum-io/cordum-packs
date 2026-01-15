package worker

import (
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/prometheus-query/internal/config"
)

func TestBuildQueryMatch(t *testing.T) {
	params := map[string]any{
		"match": []string{"up", "process_start_time_seconds"},
		"start": "1",
	}
	spec := actionSpec{ArrayKeys: []string{"match"}}
	values, err := buildQuery(params, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	matches := values["match[]"]
	if len(matches) != 2 {
		t.Fatalf("expected match entries, got %v", matches)
	}
	if got := values.Get("start"); got != "1" {
		t.Fatalf("expected start param, got %q", got)
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"query": "up"}
	if err := validateParams(params, []string{"query"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(map[string]any{}, []string{"query"}); err == nil {
		t.Fatalf("expected error for missing query")
	}
	if err := validateParams(map[string]any{"match": []string{}}, []string{"match"}); err == nil {
		t.Fatalf("expected error for empty match")
	}
}

func TestResolveAuthInline(t *testing.T) {
	w := &Worker{cfg: config.Config{AllowInlineAuth: true}}
	profile := config.Profile{Token: "profile-token"}
	bearer, _, _, err := w.resolveAuth(profile, InlineAuth{Token: "inline-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bearer != "inline-token" {
		t.Fatalf("expected inline token, got %q", bearer)
	}
}

func TestResolveSecretPrefersEnv(t *testing.T) {
	os.Setenv("PROM_TEST_TOKEN", "env-token")
	defer os.Unsetenv("PROM_TEST_TOKEN")

	if got := resolveSecret("raw-token", "PROM_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
}
