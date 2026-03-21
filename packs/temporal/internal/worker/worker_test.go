package worker

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/temporal/internal/config"
)

func TestActionSpecs(t *testing.T) {
	expected := []string{
		"workflow.start", "workflow.signal", "workflow.query", "workflow.describe",
		"workflow.cancel", "workflow.terminate", "workflow.list",
		"schedule.create", "schedule.list", "schedule.describe",
		"schedule.delete", "schedule.pause", "schedule.unpause",
	}
	for _, a := range expected {
		if _, ok := actionSpecs[a]; !ok {
			t.Errorf("missing action: %s", a)
		}
	}
	if len(actionSpecs) != len(expected) {
		t.Errorf("expected %d actions, got %d", len(expected), len(actionSpecs))
	}
}

func TestIntentClassification(t *testing.T) {
	destructive := []string{"workflow.cancel", "workflow.terminate", "schedule.delete"}
	for _, a := range destructive {
		if actionSpecs[a].Intent != "destructive" {
			t.Errorf("expected %s to be destructive", a)
		}
	}

	read := []string{"workflow.query", "workflow.describe", "workflow.list", "schedule.list", "schedule.describe"}
	for _, a := range read {
		if actionSpecs[a].Intent != "read" {
			t.Errorf("expected %s to be read", a)
		}
	}
}

func TestTaskQueueAllowed(t *testing.T) {
	cfg := config.Config{AllowedTaskQueues: []string{"prod"}}
	if !cfg.IsTaskQueueAllowed("prod") {
		t.Error("expected prod allowed")
	}
	if cfg.IsTaskQueueAllowed("dev") {
		t.Error("expected dev denied")
	}
}

func TestWorkflowAllowed(t *testing.T) {
	cfg := config.Config{DeniedWorkflows: []string{"Dangerous"}}
	if cfg.IsWorkflowAllowed("Dangerous") {
		t.Error("expected denied")
	}
	if !cfg.IsWorkflowAllowed("Safe") {
		t.Error("expected allowed")
	}
}

func TestNormalizePayload(t *testing.T) {
	if normalizePayload(nil) == nil {
		t.Fatal("expected non-nil")
	}
}
