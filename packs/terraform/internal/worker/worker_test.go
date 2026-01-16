package worker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/terraform/internal/config"
)

func TestNormalizeDir(t *testing.T) {
	base := t.TempDir()
	child := filepath.Join(base, "envs")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	resolved, err := normalizeDir(base, "envs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != child {
		t.Fatalf("expected %s, got %s", child, resolved)
	}
}

func TestEnforceDirPolicy(t *testing.T) {
	profile := config.Profile{AllowedDirs: []string{"/infra/*"}}
	if err := enforceDirPolicy(profile, "/infra/prod"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceDirPolicy(profile, "/other/env"); err == nil {
		t.Fatalf("expected error for disallowed dir")
	}

	profile = config.Profile{DeniedDirs: []string{"/infra/secret"}}
	if err := enforceDirPolicy(profile, "/infra/secret"); err == nil {
		t.Fatalf("expected error for denied dir")
	}
}

func TestAppendVars(t *testing.T) {
	params := map[string]any{"var": map[string]any{"region": "us-east-1"}}
	args := appendVars([]string{}, params)
	if len(args) != 2 || args[0] != "-var" {
		t.Fatalf("unexpected args: %v", args)
	}
}
