package worker

import (
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/jira/internal/config"
)

func TestResolvePathAliases(t *testing.T) {
	params := map[string]any{"issue_key": "ABC-1", "keep": "value"}
	path, cleaned, err := resolvePath("/rest/api/3/issue/{issue}", params, []string{"issue"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path != "/rest/api/3/issue/ABC-1" {
		t.Fatalf("unexpected path: %s", path)
	}
	if _, ok := cleaned["issue_key"]; ok {
		t.Fatalf("expected issue_key removed")
	}
	if cleaned["keep"] != "value" {
		t.Fatalf("expected keep param")
	}
}

func TestValidateParamsAlternatives(t *testing.T) {
	params := map[string]any{"accountId": "123"}
	if err := validateParams(params, []string{"account_id|accountId"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(params, []string{"issue"}); err == nil {
		t.Fatalf("expected error for missing issue")
	}
}

func TestExtractProjects(t *testing.T) {
	params := map[string]any{"issue": "PROJ-1"}
	projects := extractProjects(params)
	if len(projects) != 1 || projects[0] != "PROJ" {
		t.Fatalf("unexpected projects: %v", projects)
	}
}

func TestEnforceProjectPolicy(t *testing.T) {
	profile := config.Profile{AllowedProjects: []string{"PROJ"}}
	if err := enforceProjectPolicy(profile, []string{"PROJ"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceProjectPolicy(profile, []string{"OTHER"}); err == nil {
		t.Fatalf("expected error for disallowed project")
	}
}

func TestResolveSecret(t *testing.T) {
	os.Setenv("JIRA_TEST_TOKEN", "env-token")
	defer os.Unsetenv("JIRA_TEST_TOKEN")

	if got := resolveSecret("value-token", "JIRA_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
	os.Unsetenv("JIRA_TEST_TOKEN")
	if got := resolveSecret("value-token", "JIRA_TEST_TOKEN"); got != "value-token" {
		t.Fatalf("expected value token, got %q", got)
	}
}
