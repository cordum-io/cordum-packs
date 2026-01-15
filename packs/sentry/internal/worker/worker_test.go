package worker

import (
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/sentry/internal/config"
)

func TestNormalizeParamsProjectSplit(t *testing.T) {
	params := map[string]any{"project": "org-slug/proj-slug"}
	normalized := normalizeParams(params)
	if normalized["org"] != "org-slug" {
		t.Fatalf("expected org to be set")
	}
	if normalized["project"] != "proj-slug" {
		t.Fatalf("expected project to be slug")
	}
	if normalized["project_slug"] != "proj-slug" {
		t.Fatalf("expected project_slug to be set")
	}
}

func TestResolvePath(t *testing.T) {
	params := map[string]any{
		"org":     "my-org",
		"project": "my-project",
	}
	pathValue, cleaned, err := resolvePath("/projects/{org}/{project}/issues/", params, []string{"org", "project"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pathValue != "/projects/my-org/my-project/issues/" {
		t.Fatalf("unexpected path: %s", pathValue)
	}
	if _, ok := cleaned["org"]; ok {
		t.Fatalf("expected org to be removed")
	}
	if _, ok := cleaned["project"]; ok {
		t.Fatalf("expected project to be removed")
	}
}

func TestApplyDefaults(t *testing.T) {
	params := map[string]any{"issue_id": "1"}
	defaults := map[string]any{"status": "resolved"}
	out := applyDefaults(params, defaults)
	if out["status"] != "resolved" {
		t.Fatalf("expected default to be applied")
	}
}

func TestEnforcePolicies(t *testing.T) {
	profile := config.Profile{AllowedOrgs: []string{"org-*"}}
	if err := enforceOrgPolicy(profile, "org-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceOrgPolicy(profile, "other"); err == nil {
		t.Fatalf("expected error for disallowed org")
	}

	profile = config.Profile{DeniedProjects: []string{"org-1/secret"}}
	if err := enforceProjectPolicy(profile, "org-1/secret"); err == nil {
		t.Fatalf("expected error for denied project")
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"issue_id": "1"}
	if err := validateParams(params, []string{"issue_id|issueId"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(map[string]any{}, []string{"issue_id"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}

func TestResolveSecret(t *testing.T) {
	os.Setenv("SENTRY_TEST_TOKEN", "env-token")
	defer os.Unsetenv("SENTRY_TEST_TOKEN")

	if got := resolveSecret("raw-token", "SENTRY_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
	os.Unsetenv("SENTRY_TEST_TOKEN")
	if got := resolveSecret("raw-token", "SENTRY_TEST_TOKEN"); got != "raw-token" {
		t.Fatalf("expected raw token, got %q", got)
	}
}
