package worker

import (
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/github/internal/config"
)

func TestResolveRepo(t *testing.T) {
	owner, repo, full, err := resolveRepo(JobInput{Owner: "cordum-io", Repo: "cordum-packs"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if full != "cordum-io/cordum-packs" {
		t.Fatalf("unexpected repo: %s/%s", owner, repo)
	}

	_, _, full, err = resolveRepo(JobInput{Repository: "cordum-io/cordum-packs"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if full != "cordum-io/cordum-packs" {
		t.Fatalf("unexpected full repo: %s", full)
	}
}

func TestEnforceRepoPolicy(t *testing.T) {
	profile := config.Profile{AllowedRepos: []string{"cordum-io/*"}}
	if err := enforceRepoPolicy(profile, "cordum-io/cordum-packs"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceRepoPolicy(profile, "other/repo"); err == nil {
		t.Fatalf("expected error for disallowed repo")
	}

	profile = config.Profile{DeniedRepos: []string{"cordum-io/secret"}}
	if err := enforceRepoPolicy(profile, "cordum-io/secret"); err == nil {
		t.Fatalf("expected error for denied repo")
	}
}

func TestResolveSecret(t *testing.T) {
	os.Setenv("GITHUB_TEST_TOKEN", "env-token")
	defer os.Unsetenv("GITHUB_TEST_TOKEN")

	if got := resolveSecret("value-token", "GITHUB_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
	os.Unsetenv("GITHUB_TEST_TOKEN")
	if got := resolveSecret("value-token", "GITHUB_TEST_TOKEN"); got != "value-token" {
		t.Fatalf("expected value token, got %q", got)
	}
}
