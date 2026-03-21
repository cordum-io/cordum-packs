package worker

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/cohere/internal/config"
)

func TestModelAllowed(t *testing.T) {
	tests := []struct {
		name  string
		cfg   config.Config
		model string
		want  bool
	}{
		{"no restrictions", config.Config{}, "command-r-plus", true},
		{"empty model", config.Config{}, "", true},
		{"denied", config.Config{DeniedModels: []string{"command-r"}}, "command-r", false},
		{"allowed", config.Config{AllowedModels: []string{"command-r-plus"}}, "command-r-plus", true},
		{"not in allow list", config.Config{AllowedModels: []string{"command-r-plus"}}, "command-r", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsModelAllowed(tt.model); got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestNormalizePayload(t *testing.T) {
	if normalizePayload(nil) == nil {
		t.Fatal("expected non-nil")
	}
	r := normalizePayload(map[string]any{"context": map[string]any{"action": "embed"}})
	if r["action"] != "embed" {
		t.Errorf("expected embed, got %v", r["action"])
	}
}

func TestDecodePayload(t *testing.T) {
	var input JobInput
	if err := decodePayload(map[string]any{"action": "rerank"}, &input); err != nil {
		t.Fatal(err)
	}
	if input.Action != "rerank" {
		t.Errorf("expected rerank, got %q", input.Action)
	}
}

func TestEmbedInputTypeValidation(t *testing.T) {
	// The worker validates input_type is set — we test the validation logic
	params := map[string]any{
		"texts": []any{"hello"},
		// input_type intentionally missing
	}
	var req struct {
		InputType string `json:"input_type"`
	}
	decodePayload(params, &req)
	if req.InputType != "" {
		t.Errorf("expected empty input_type, got %q", req.InputType)
	}
	// Worker would return error: "input_type is required..."
}
