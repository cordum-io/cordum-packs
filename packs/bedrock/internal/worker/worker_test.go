package worker

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/bedrock/internal/config"
)

func TestActionSpecs(t *testing.T) {
	expected := []string{"invoke", "converse", "embed", "kb.query", "kb.retrieve", "agent.invoke", "models.list", "models.get"}
	for _, a := range expected {
		if _, ok := actionSpecs[a]; !ok {
			t.Errorf("missing action: %s", a)
		}
	}
	if len(actionSpecs) != len(expected) {
		t.Errorf("expected %d, got %d", len(expected), len(actionSpecs))
	}
}

func TestIntentClassification(t *testing.T) {
	generate := []string{"invoke", "converse", "embed"}
	for _, a := range generate {
		if actionSpecs[a].Intent != "generate" {
			t.Errorf("expected %s to be generate", a)
		}
	}

	write := []string{"kb.query", "kb.retrieve", "agent.invoke"}
	for _, a := range write {
		if actionSpecs[a].Intent != "write" {
			t.Errorf("expected %s to be write", a)
		}
	}

	read := []string{"models.list", "models.get"}
	for _, a := range read {
		if actionSpecs[a].Intent != "read" {
			t.Errorf("expected %s to be read", a)
		}
	}
}

func TestModelAllowed(t *testing.T) {
	cfg := config.Config{AllowedModels: []string{"anthropic", "amazon.titan"}}
	if !cfg.IsModelAllowed("anthropic.claude-v2") {
		t.Error("expected anthropic model allowed")
	}
	if !cfg.IsModelAllowed("amazon.titan-embed-text-v2:0") {
		t.Error("expected titan model allowed")
	}
	if cfg.IsModelAllowed("meta.llama3-8b") {
		t.Error("expected meta model denied")
	}
}

func TestModelDenied(t *testing.T) {
	cfg := config.Config{DeniedModels: []string{"meta.llama"}}
	if cfg.IsModelAllowed("meta.llama3-8b-instruct-v1:0") {
		t.Error("expected meta.llama denied")
	}
	if !cfg.IsModelAllowed("anthropic.claude-v2") {
		t.Error("expected anthropic allowed")
	}
}

func TestNormalizePayload(t *testing.T) {
	if normalizePayload(nil) == nil {
		t.Fatal("expected non-nil")
	}
}
