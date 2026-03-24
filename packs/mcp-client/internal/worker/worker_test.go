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

func TestToolAllowed(t *testing.T) {
	tests := []struct {
		name   string
		tool   string
		allow  []string
		deny   []string
		expect bool
	}{
		{"no policy allows all", "anything", nil, nil, true},
		{"deny list blocks", "blocked-tool", nil, []string{"blocked-tool"}, false},
		{"deny list case insensitive", "Blocked-Tool", nil, []string{"blocked-tool"}, false},
		{"deny list no match", "safe-tool", nil, []string{"blocked-tool"}, true},
		{"allow list permits match", "good-tool", []string{"good-tool"}, nil, true},
		{"allow list blocks non-match", "other-tool", []string{"good-tool"}, nil, false},
		{"deny takes priority over allow", "tool", []string{"tool"}, []string{"tool"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toolAllowed(tt.tool, tt.allow, tt.deny)
			if got != tt.expect {
				t.Errorf("toolAllowed(%q, %v, %v) = %v, want %v", tt.tool, tt.allow, tt.deny, got, tt.expect)
			}
		})
	}
}

func TestIsAllowedMethod(t *testing.T) {
	allowed := []string{"tools/call", "tools/list", "resources/list", "resources/templates/list", "resources/read", "ping"}
	for _, m := range allowed {
		if !isAllowedMethod(m) {
			t.Errorf("isAllowedMethod(%q) = false, want true", m)
		}
	}
	denied := []string{"", "admin/shutdown", "tools/delete", "unknown"}
	for _, m := range denied {
		if isAllowedMethod(m) {
			t.Errorf("isAllowedMethod(%q) = true, want false", m)
		}
	}
}

func TestValidateHTTPURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"valid https", "https://example.com/api", false},
		{"valid http", "http://localhost:8080", false},
		{"missing host", "http://", true},
		{"invalid scheme", "ftp://example.com", true},
		{"credentials in url", "https://user:pass@example.com", true},
		{"empty string", "", true},
		{"no scheme", "example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateHTTPURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateHTTPURL(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
		})
	}
}

func TestMergeStringMap(t *testing.T) {
	base := map[string]string{"a": "1", "b": "2"}
	overlay := map[string]string{"b": "override", "c": "3"}
	result := mergeStringMap(base, overlay)
	if result["a"] != "1" {
		t.Errorf("expected a=1, got %q", result["a"])
	}
	if result["b"] != "override" {
		t.Errorf("expected b=override, got %q", result["b"])
	}
	if result["c"] != "3" {
		t.Errorf("expected c=3, got %q", result["c"])
	}
	// Verify nil base
	result = mergeStringMap(nil, overlay)
	if result["b"] != "override" {
		t.Errorf("nil base: expected b=override, got %q", result["b"])
	}
}

func TestHasInlineServerOverrides(t *testing.T) {
	if hasInlineServerOverrides(JobInput{}) {
		t.Error("empty input should have no overrides")
	}
	if !hasInlineServerOverrides(JobInput{URL: "https://example.com"}) {
		t.Error("URL should count as override")
	}
	if !hasInlineServerOverrides(JobInput{Command: "echo"}) {
		t.Error("Command should count as override")
	}
	if !hasInlineServerOverrides(JobInput{Headers: map[string]string{"X-Key": "val"}}) {
		t.Error("Headers should count as override")
	}
}

func TestNormalizePayload(t *testing.T) {
	// nil returns empty map
	result := normalizePayload(nil)
	if result == nil {
		t.Error("nil input should return empty map")
	}
	// payload with "context" key extracts nested
	payload := map[string]any{
		"context": map[string]any{"tool": "test"},
	}
	result = normalizePayload(payload)
	if result["tool"] != "test" {
		t.Errorf("expected context extraction, got %v", result)
	}
	// payload without context returns as-is
	plain := map[string]any{"tool": "direct"}
	result = normalizePayload(plain)
	if result["tool"] != "direct" {
		t.Errorf("expected pass-through, got %v", result)
	}
}
