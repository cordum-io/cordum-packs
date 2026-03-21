package temporalclient

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/temporal/internal/config"
)

func TestNewClient(t *testing.T) {
	c := NewClient(config.Config{
		TemporalHost: "localhost:7233",
		Namespace:    "test-ns",
		Identity:     "test-worker",
	})
	if c.baseURL != "http://localhost:7233" {
		t.Errorf("expected http://localhost:7233, got %q", c.baseURL)
	}
	if c.namespace != "test-ns" {
		t.Errorf("expected test-ns, got %q", c.namespace)
	}
}

func TestNewClientHTTPS(t *testing.T) {
	c := NewClient(config.Config{
		TemporalHost: "https://temporal.example.com",
		Namespace:    "prod",
	})
	if c.baseURL != "https://temporal.example.com" {
		t.Errorf("expected https URL, got %q", c.baseURL)
	}
}

func TestStartWorkflowValidation(t *testing.T) {
	c := NewClient(config.Config{TemporalHost: "localhost:7233", Namespace: "default"})

	_, err := c.StartWorkflow(nil, map[string]any{})
	if err == nil || err.Error() != "workflow_type is required" {
		t.Errorf("expected validation error, got %v", err)
	}

	_, err = c.StartWorkflow(nil, map[string]any{"workflow_type": "MyWorkflow"})
	if err == nil || err.Error() != "task_queue is required" {
		t.Errorf("expected task_queue error, got %v", err)
	}
}

func TestSignalWorkflowValidation(t *testing.T) {
	c := NewClient(config.Config{TemporalHost: "localhost:7233", Namespace: "default"})

	_, err := c.SignalWorkflow(nil, map[string]any{})
	if err == nil || err.Error() != "workflow_id and signal_name are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestQueryWorkflowValidation(t *testing.T) {
	c := NewClient(config.Config{TemporalHost: "localhost:7233", Namespace: "default"})

	_, err := c.QueryWorkflow(nil, map[string]any{})
	if err == nil || err.Error() != "workflow_id and query_type are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestDescribeWorkflowValidation(t *testing.T) {
	c := NewClient(config.Config{TemporalHost: "localhost:7233", Namespace: "default"})

	_, err := c.DescribeWorkflow(nil, map[string]any{})
	if err == nil || err.Error() != "workflow_id is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestCancelWorkflowValidation(t *testing.T) {
	c := NewClient(config.Config{TemporalHost: "localhost:7233", Namespace: "default"})

	_, err := c.CancelWorkflow(nil, map[string]any{})
	if err == nil || err.Error() != "workflow_id is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestTerminateWorkflowValidation(t *testing.T) {
	c := NewClient(config.Config{TemporalHost: "localhost:7233", Namespace: "default"})

	_, err := c.TerminateWorkflow(nil, map[string]any{})
	if err == nil || err.Error() != "workflow_id is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestTaskQueueAllowed(t *testing.T) {
	cfg := config.Config{AllowedTaskQueues: []string{"prod-queue", "staging-queue"}}
	if !cfg.IsTaskQueueAllowed("prod-queue") {
		t.Error("expected prod-queue allowed")
	}
	if cfg.IsTaskQueueAllowed("dev-queue") {
		t.Error("expected dev-queue denied")
	}
	if !cfg.IsTaskQueueAllowed("") {
		t.Error("expected empty queue allowed")
	}
}

func TestWorkflowAllowed(t *testing.T) {
	cfg := config.Config{DeniedWorkflows: []string{"DangerousWorkflow"}}
	if cfg.IsWorkflowAllowed("DangerousWorkflow") {
		t.Error("expected DangerousWorkflow denied")
	}
	if !cfg.IsWorkflowAllowed("SafeWorkflow") {
		t.Error("expected SafeWorkflow allowed")
	}
}
