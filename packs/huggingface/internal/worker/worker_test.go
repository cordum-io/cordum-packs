package worker

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/huggingface/internal/config"
)

func TestTaskAllowed(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		task string
		want bool
	}{
		{"no restrictions", config.Config{}, "text-generation", true},
		{"empty task", config.Config{}, "", true},
		{"denied", config.Config{DeniedTasks: []string{"image-classification"}}, "image-classification", false},
		{"allowed", config.Config{AllowedTasks: []string{"text-generation", "summarization"}}, "text-generation", true},
		{"not in allow list", config.Config{AllowedTasks: []string{"text-generation"}}, "fill-mask", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsTaskAllowed(tt.task); got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestNormalizePayload(t *testing.T) {
	if normalizePayload(nil) == nil {
		t.Fatal("expected non-nil")
	}
	r := normalizePayload(map[string]any{"context": map[string]any{"action": "inference"}})
	if r["action"] != "inference" {
		t.Errorf("expected inference, got %v", r["action"])
	}
}

func TestDecodePayload(t *testing.T) {
	var input JobInput
	if err := decodePayload(map[string]any{"action": "embed", "profile": "default"}, &input); err != nil {
		t.Fatal(err)
	}
	if input.Action != "embed" {
		t.Errorf("expected embed, got %q", input.Action)
	}
}
