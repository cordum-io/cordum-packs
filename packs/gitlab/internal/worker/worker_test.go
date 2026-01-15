package worker

import (
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/gitlab/internal/config"
)

func TestResolvePathProject(t *testing.T) {
	params := map[string]any{
		"project_path_with_namespace": "group/project",
		"issue_iid":                   7,
		"state":                       "opened",
	}
	pathValue, cleaned, err := resolvePath("/projects/{project}/issues/{issue_iid}", params, []string{"project", "issue_iid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pathValue != "/projects/group%2Fproject/issues/7" {
		t.Fatalf("unexpected path: %s", pathValue)
	}
	if _, ok := cleaned["project_path_with_namespace"]; ok {
		t.Fatalf("expected project param to be removed")
	}
	if _, ok := cleaned["issue_iid"]; ok {
		t.Fatalf("expected issue_iid to be removed")
	}
	if cleaned["state"] != "opened" {
		t.Fatalf("expected state to remain in params")
	}
}

func TestNormalizeParams(t *testing.T) {
	params := map[string]any{
		"projectId":    101,
		"sourceBranch": "feature",
		"targetBranch": "main",
	}
	normalized := normalizeParams(params)
	if normalized["project_id"] != 101 {
		t.Fatalf("expected project_id to be set")
	}
	if normalized["source_branch"] != "feature" {
		t.Fatalf("expected source_branch to be set")
	}
	if normalized["target_branch"] != "main" {
		t.Fatalf("expected target_branch to be set")
	}
}

func TestEnforceProjectPolicy(t *testing.T) {
	profile := config.Profile{AllowedProjects: []string{"group/*"}}
	if err := enforceProjectPolicy(profile, "group/project"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceProjectPolicy(profile, "other/project"); err == nil {
		t.Fatalf("expected error for disallowed project")
	}

	profile = config.Profile{DeniedProjects: []string{"group/secret"}}
	if err := enforceProjectPolicy(profile, "group/secret"); err == nil {
		t.Fatalf("expected error for denied project")
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"projectId": "123"}
	if err := validateParams(params, []string{"project|project_id|projectId"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(map[string]any{}, []string{"project"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}

func TestResolveSecret(t *testing.T) {
	os.Setenv("GITLAB_TEST_TOKEN", "env-token")
	defer os.Unsetenv("GITLAB_TEST_TOKEN")

	if got := resolveSecret("value-token", "GITLAB_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
	os.Unsetenv("GITLAB_TEST_TOKEN")
	if got := resolveSecret("value-token", "GITLAB_TEST_TOKEN"); got != "value-token" {
		t.Fatalf("expected value token, got %q", got)
	}
}
