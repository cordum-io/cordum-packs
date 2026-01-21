package worker

import (
	"os"
	"testing"
)

func TestResolveSecret(t *testing.T) {
	os.Setenv("MCP_CLIENT_TEST_SECRET", "env-secret")
	defer os.Unsetenv("MCP_CLIENT_TEST_SECRET")

	if got := resolveSecret("value-secret", "MCP_CLIENT_TEST_SECRET"); got != "env-secret" {
		t.Fatalf("expected env secret, got %q", got)
	}
	os.Unsetenv("MCP_CLIENT_TEST_SECRET")
	if got := resolveSecret("value-secret", "MCP_CLIENT_TEST_SECRET"); got != "value-secret" {
		t.Fatalf("expected value secret, got %q", got)
	}
}
