package worker

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/anthropic/internal/config"
)

// TestBuildMessagesRequest_ModelValidation tests model allow/deny logic.
func TestBuildMessagesRequest_ModelValidation(t *testing.T) {
	cfg := config.Config{ThinkingEnabled: false}

	tests := []struct {
		name      string
		profile   config.Profile
		params    map[string]any
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid model allowed",
			profile: config.Profile{Name: "default", MaxTokensLimit: 4096},
			params: map[string]any{
				"model":      "claude-sonnet-4-6",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
			},
			wantErr: false,
		},
		{
			name:    "model in deny list",
			profile: config.Profile{Name: "restricted", MaxTokensLimit: 4096, DeniedModels: []string{"claude-opus-4-6"}},
			params: map[string]any{
				"model":      "claude-opus-4-6",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
			},
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:    "model not in allow list",
			profile: config.Profile{Name: "limited", MaxTokensLimit: 4096, AllowedModels: []string{"claude-haiku-4-5"}},
			params: map[string]any{
				"model":      "claude-opus-4-6",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
			},
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:    "model in allow list passes",
			profile: config.Profile{Name: "limited", MaxTokensLimit: 4096, AllowedModels: []string{"claude-haiku-4-5"}},
			params: map[string]any{
				"model":      "claude-haiku-4-5",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
			},
			wantErr: false,
		},
		{
			name:    "missing model",
			profile: config.Profile{Name: "default", MaxTokensLimit: 4096},
			params: map[string]any{
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
			},
			wantErr:   true,
			errSubstr: "model is required",
		},
		{
			name:    "missing max_tokens",
			profile: config.Profile{Name: "default", MaxTokensLimit: 4096},
			params: map[string]any{
				"model":    "claude-sonnet-4-6",
				"messages": []any{map[string]any{"role": "user", "content": "hi"}},
			},
			wantErr:   true,
			errSubstr: "max_tokens is required",
		},
		{
			name:    "max_tokens exceeds limit",
			profile: config.Profile{Name: "default", MaxTokensLimit: 1000},
			params: map[string]any{
				"model":      "claude-sonnet-4-6",
				"max_tokens": float64(5000),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
			},
			wantErr:   true,
			errSubstr: "exceeds profile limit",
		},
		{
			name:    "empty messages",
			profile: config.Profile{Name: "default", MaxTokensLimit: 4096},
			params: map[string]any{
				"model":      "claude-sonnet-4-6",
				"max_tokens": float64(100),
				"messages":   []any{},
			},
			wantErr:   true,
			errSubstr: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildMessagesRequest(tt.params, tt.profile, cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestBuildMessagesRequest_ThinkingValidation tests extended thinking config checks.
func TestBuildMessagesRequest_ThinkingValidation(t *testing.T) {
	tests := []struct {
		name      string
		cfg       config.Config
		profile   config.Profile
		params    map[string]any
		wantErr   bool
		errSubstr string
	}{
		{
			name: "thinking disabled at profile and global level",
			cfg:  config.Config{ThinkingEnabled: false},
			profile: config.Profile{
				Name:              "default",
				MaxTokensLimit:    4096,
				ThinkingEnabled:   false,
				ThinkingMaxBudget: 10000,
			},
			params: map[string]any{
				"model":      "claude-sonnet-4-6",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
				"thinking":   map[string]any{"type": "enabled", "budget_tokens": float64(5000)},
			},
			wantErr:   true,
			errSubstr: "not enabled",
		},
		{
			name: "thinking enabled at profile level",
			cfg:  config.Config{ThinkingEnabled: false},
			profile: config.Profile{
				Name:              "default",
				MaxTokensLimit:    4096,
				ThinkingEnabled:   true,
				ThinkingMaxBudget: 10000,
			},
			params: map[string]any{
				"model":      "claude-sonnet-4-6",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
				"thinking":   map[string]any{"type": "enabled", "budget_tokens": float64(5000)},
			},
			wantErr: false,
		},
		{
			name: "thinking enabled at global level",
			cfg:  config.Config{ThinkingEnabled: true},
			profile: config.Profile{
				Name:              "default",
				MaxTokensLimit:    4096,
				ThinkingEnabled:   false,
				ThinkingMaxBudget: 10000,
			},
			params: map[string]any{
				"model":      "claude-sonnet-4-6",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
				"thinking":   map[string]any{"type": "enabled", "budget_tokens": float64(5000)},
			},
			wantErr: false,
		},
		{
			name: "thinking budget exceeds limit",
			cfg:  config.Config{ThinkingEnabled: true},
			profile: config.Profile{
				Name:              "default",
				MaxTokensLimit:    4096,
				ThinkingEnabled:   true,
				ThinkingMaxBudget: 5000,
			},
			params: map[string]any{
				"model":      "claude-sonnet-4-6",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
				"thinking":   map[string]any{"type": "enabled", "budget_tokens": float64(10000)},
			},
			wantErr:   true,
			errSubstr: "exceeds limit",
		},
		{
			name: "no thinking block — always passes",
			cfg:  config.Config{ThinkingEnabled: false},
			profile: config.Profile{
				Name:              "default",
				MaxTokensLimit:    4096,
				ThinkingEnabled:   false,
				ThinkingMaxBudget: 0,
			},
			params: map[string]any{
				"model":      "claude-sonnet-4-6",
				"max_tokens": float64(100),
				"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildMessagesRequest(tt.params, tt.profile, tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestNormalizePayload tests payload normalization.
func TestNormalizePayload(t *testing.T) {
	t.Run("nil payload", func(t *testing.T) {
		result := normalizePayload(nil)
		if result == nil {
			t.Fatal("expected non-nil map")
		}
	})

	t.Run("payload with context key", func(t *testing.T) {
		payload := map[string]any{
			"context": map[string]any{
				"action": "messages.create",
				"params": map[string]any{"model": "claude-sonnet-4-6"},
			},
		}
		result := normalizePayload(payload)
		if result["action"] != "messages.create" {
			t.Errorf("expected action=messages.create, got %v", result["action"])
		}
	})

	t.Run("payload without context key", func(t *testing.T) {
		payload := map[string]any{
			"action": "messages.create",
		}
		result := normalizePayload(payload)
		if result["action"] != "messages.create" {
			t.Errorf("expected action=messages.create, got %v", result["action"])
		}
	})
}

// TestNormalizeJobStatus tests job status normalization.
func TestNormalizeJobStatus(t *testing.T) {
	tests := []struct {
		input  any
		expect string
	}{
		{"succeeded", "succeeded"},
		{"success", "succeeded"},
		{"SUCCEEDED", "succeeded"},
		{"JOB_STATUS_SUCCEEDED", "succeeded"},
		{"failed", "failed"},
		{"failed_retryable", "failed"},
		{"denied", "denied"},
		{"cancelled", "cancelled"},
		{"canceled", "cancelled"},
		{"timeout", "timeout"},
		{"timed_out", "timeout"},
		{"running", "running"},
		{"pending", "pending"},
		{float64(5), "succeeded"},
		{float64(6), "failed"},
		{float64(7), "cancelled"},
		{float64(8), "denied"},
		{float64(9), "timeout"},
		{nil, ""},
		{42, ""},
	}

	for _, tt := range tests {
		got := normalizeJobStatus(tt.input)
		if got != tt.expect {
			t.Errorf("normalizeJobStatus(%v) = %q, want %q", tt.input, got, tt.expect)
		}
	}
}

// TestTerminalJobStatus tests terminal status detection.
func TestTerminalJobStatus(t *testing.T) {
	terminal := []string{"succeeded", "failed", "cancelled", "denied", "timeout"}
	for _, s := range terminal {
		if !terminalJobStatus(s) {
			t.Errorf("expected %q to be terminal", s)
		}
	}

	nonTerminal := []string{"pending", "running", "scheduled", "dispatched", ""}
	for _, s := range nonTerminal {
		if terminalJobStatus(s) {
			t.Errorf("expected %q to be non-terminal", s)
		}
	}
}

// TestExtractJobResult tests result extraction from job maps.
func TestExtractJobResult(t *testing.T) {
	tests := []struct {
		name   string
		job    map[string]any
		hasVal bool
	}{
		{"result key", map[string]any{"result": "ok"}, true},
		{"output key", map[string]any{"output": "ok"}, true},
		{"payload key", map[string]any{"payload": "ok"}, true},
		{"data key", map[string]any{"data": "ok"}, true},
		{"no result", map[string]any{"status": "done"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJobResult(tt.job)
			if tt.hasVal && result == nil {
				t.Error("expected non-nil result")
			}
			if !tt.hasVal && result != nil {
				t.Errorf("expected nil result, got %v", result)
			}
		})
	}
}

// TestExtractJobError tests error extraction from job maps.
func TestExtractJobError(t *testing.T) {
	tests := []struct {
		name   string
		job    map[string]any
		expect string
	}{
		{"error string", map[string]any{"error": "auth failed"}, "auth failed"},
		{"message string", map[string]any{"message": "rate limited"}, "rate limited"},
		{"reason string", map[string]any{"reason": "denied"}, "denied"},
		{"error map with message", map[string]any{"error": map[string]any{"message": "nested error"}}, "nested error"},
		{"empty error", map[string]any{"error": ""}, ""},
		{"no error keys", map[string]any{"status": "ok"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJobError(tt.job)
			if got != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, got)
			}
		})
	}
}

// TestResolveAPIKey tests API key resolution priority.
func TestResolveAPIKey(t *testing.T) {
	w := &Worker{
		cfg: config.Config{
			AllowInlineAuth:    true,
			AllowInlineSecrets: true,
		},
	}

	// Inline auth takes priority
	profile := config.Profile{Name: "default", APIKey: "profile-key"}
	key := w.resolveAPIKey(profile, &InlineAuth{APIKey: "inline-key"})
	if key != "inline-key" {
		t.Errorf("expected inline-key, got %q", key)
	}

	// Falls back to profile key when no inline
	key = w.resolveAPIKey(profile, nil)
	if key != "profile-key" {
		t.Errorf("expected profile-key, got %q", key)
	}

	// Inline auth disabled
	w.cfg.AllowInlineAuth = false
	key = w.resolveAPIKey(profile, &InlineAuth{APIKey: "inline-key"})
	if key != "profile-key" {
		t.Errorf("expected profile-key when inline disabled, got %q", key)
	}

	// Inline secrets disabled but env var allowed
	w.cfg.AllowInlineAuth = true
	w.cfg.AllowInlineSecrets = false
	key = w.resolveAPIKey(profile, &InlineAuth{APIKey: "inline-key"})
	if key != "profile-key" {
		t.Errorf("expected profile-key when inline secrets disabled, got %q", key)
	}
}

// TestStringFromMap tests map string extraction.
func TestStringFromMap(t *testing.T) {
	m := map[string]any{
		"name":  "test",
		"count": float64(42),
		"empty": "",
	}

	if got := stringFromMap(m, "name"); got != "test" {
		t.Errorf("expected 'test', got %q", got)
	}
	if got := stringFromMap(m, "missing"); got != "" {
		t.Errorf("expected '', got %q", got)
	}
	if got := stringFromMap(m, "count"); got != "" {
		t.Errorf("expected '' for non-string, got %q", got)
	}
}

// TestIntFromMap tests map int extraction.
func TestIntFromMap(t *testing.T) {
	m := map[string]any{
		"float":   float64(42),
		"int":     int(7),
		"string":  "not a number",
		"missing": nil,
	}

	if got := intFromMap(m, "float"); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}
	if got := intFromMap(m, "int"); got != 7 {
		t.Errorf("expected 7, got %d", got)
	}
	if got := intFromMap(m, "string"); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
	if got := intFromMap(m, "nonexistent"); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
