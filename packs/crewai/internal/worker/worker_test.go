package worker

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"

	"github.com/cordum-io/cordum-packs/packs/crewai/internal/config"
)

func TestHandleJobRejectsUngovernedRuns(t *testing.T) {
	t.Parallel()

	w := newTestWorker(func(context.Context, sidecarExecuteRequest) (sidecarExecuteResponse, error) {
		t.Fatal("sidecar should not be called")
		return sidecarExecuteResponse{}, nil
	})

	disabled := false
	_, err := w.handleJob(testRuntimeContext("job.crewai.task"), map[string]any{
		"task_config": map[string]any{
			"description": "Do the task",
		},
		"tool_governance": &disabled,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandleJobMapsCrewTopicToCrewRun(t *testing.T) {
	t.Parallel()

	var captured sidecarExecuteRequest
	w := newTestWorker(func(_ context.Context, req sidecarExecuteRequest) (sidecarExecuteResponse, error) {
		captured = req
		return sidecarExecuteResponse{
			OK: true,
			Result: map[string]any{
				"crew_output": "done",
				"tool_calls": []any{
					map[string]any{"tool_name": "search", "status": "succeeded"},
				},
			},
		}, nil
	})

	_, err := w.handleJob(testRuntimeContext("job.crewai.crew"), map[string]any{
		"crew_config": map[string]any{
			"agents": []any{map[string]any{"role": "Researcher", "goal": "Research"}},
			"tasks":  []any{map[string]any{"description": "Find facts", "agent_role": "Researcher"}},
		},
		"input": map[string]any{"query": "Cordum"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if captured.Action != actionCrewRun {
		t.Fatalf("action = %q", captured.Action)
	}
	inputMap, ok := captured.Input.(map[string]any)
	if !ok {
		t.Fatalf("expected map sidecar input, got %T", captured.Input)
	}
	if _, ok := inputMap["crew_config"].(map[string]any); !ok {
		t.Fatalf("expected crew_config in sidecar input")
	}
	if captured.Config["tenant_id"] != "tenant-default" {
		t.Fatalf("tenant_id = %v", captured.Config["tenant_id"])
	}
	if captured.Config["actor_type"] != "human" {
		t.Fatalf("actor_type = %v", captured.Config["actor_type"])
	}
}

func TestHandleJobMapsTaskTopicToTaskRun(t *testing.T) {
	t.Parallel()

	var captured sidecarExecuteRequest
	w := newTestWorker(func(_ context.Context, req sidecarExecuteRequest) (sidecarExecuteResponse, error) {
		captured = req
		return sidecarExecuteResponse{
			OK: true,
			Result: map[string]any{
				"task_outputs": []any{"result"},
				"tokens_used":  map[string]any{"total_tokens": 42},
			},
		}, nil
	})

	result, err := w.handleJob(testRuntimeContext("job.crewai.task"), map[string]any{
		"task_config": map[string]any{
			"description": "Summarize findings",
			"agent_config": map[string]any{
				"role": "Writer",
				"goal": "Write summary",
			},
		},
		"context": []any{"prior output"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if captured.Action != actionTaskRun {
		t.Fatalf("action = %q", captured.Action)
	}
	if result.TokensUsed["total_tokens"] != 42 {
		t.Fatalf("tokens = %+v", result.TokensUsed)
	}
}

func TestHandleJobReturnsValidationError(t *testing.T) {
	t.Parallel()

	w := newTestWorker(func(context.Context, sidecarExecuteRequest) (sidecarExecuteResponse, error) {
		t.Fatal("sidecar should not be called")
		return sidecarExecuteResponse{}, nil
	})

	_, err := w.handleJob(testRuntimeContext("job.crewai.crew"), map[string]any{
		"crew_config": map[string]any{
			"agents": []any{},
			"tasks":  []any{},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func newTestWorker(exec func(context.Context, sidecarExecuteRequest) (sidecarExecuteResponse, error)) *Worker {
	return &Worker{
		cfg: config.Config{
			RequestTimeout: 5 * time.Second,
			TenantID:       "tenant-default",
			ToolTopic:      "job.crewai.toolcall",
		},
		workerID:    "worker-test",
		executeFunc: exec,
	}
}

func testRuntimeContext(topic string) runtime.Context {
	return runtime.Context{
		Job: &agentv1.JobRequest{
			JobId:       "job-123",
			Topic:       topic,
			TenantId:    "tenant-default",
			PrincipalId: "principal-123",
			Meta: &agentv1.JobMetadata{
				ActorId:   "actor-123",
				ActorType: agentv1.ActorType_ACTOR_TYPE_HUMAN,
			},
		},
		Packet: &agentv1.BusPacket{
			TraceId: "trace-123",
		},
	}
}
