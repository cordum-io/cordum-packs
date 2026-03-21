package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"

	"github.com/cordum-io/cordum-packs/packs/n8n/internal/config"
)

type fakeClient struct {
	listWorkflowsResult   map[string]any
	getWorkflowResult     map[string]any
	executeResult         map[string]any
	getExecutionResults   []map[string]any
	activateResult        map[string]any
	deactivateResult      map[string]any
	listExecutionsResult  map[string]any
	listCredentialsResult map[string]any
	executeWorkflowID     string
	executePayload        map[string]any
	getExecutionCalls     int
}

func (f *fakeClient) ListWorkflows(_ context.Context, _ map[string]any) (map[string]any, error) {
	return cloneMap(f.listWorkflowsResult), nil
}
func (f *fakeClient) GetWorkflow(_ context.Context, _ string) (map[string]any, error) {
	return cloneMap(f.getWorkflowResult), nil
}
func (f *fakeClient) ExecuteWorkflow(_ context.Context, workflowID string, payload map[string]any) (map[string]any, error) {
	f.executeWorkflowID = workflowID
	f.executePayload = payload
	return cloneMap(f.executeResult), nil
}
func (f *fakeClient) GetExecution(_ context.Context, _ string, _ bool) (map[string]any, error) {
	if len(f.getExecutionResults) == 0 {
		return map[string]any{"status": "success"}, nil
	}
	result := cloneMap(f.getExecutionResults[0])
	f.getExecutionCalls++
	if len(f.getExecutionResults) > 1 {
		f.getExecutionResults = f.getExecutionResults[1:]
	}
	return result, nil
}
func (f *fakeClient) ListExecutions(_ context.Context, _ map[string]any) (map[string]any, error) {
	return cloneMap(f.listExecutionsResult), nil
}
func (f *fakeClient) ActivateWorkflow(_ context.Context, _ string) (map[string]any, error) {
	return cloneMap(f.activateResult), nil
}
func (f *fakeClient) DeactivateWorkflow(_ context.Context, _ string) (map[string]any, error) {
	return cloneMap(f.deactivateResult), nil
}
func (f *fakeClient) ListCredentials(_ context.Context) (map[string]any, error) {
	return cloneMap(f.listCredentialsResult), nil
}

func TestActionSpecs(t *testing.T) {
	expected := []string{actionWorkflowList, actionWorkflowGet, actionWorkflowExecute, actionWorkflowActivate, actionWorkflowDeactivate, actionExecutionGet, actionExecutionList, actionCredentialsList}
	for _, action := range expected {
		if _, ok := actionSpecs[action]; !ok {
			t.Errorf("missing action spec: %s", action)
		}
	}
	if len(actionSpecs) != len(expected) {
		t.Fatalf("expected %d action specs, got %d", len(expected), len(actionSpecs))
	}
}

func TestHandleJobRejectsWrongTopic(t *testing.T) {
	w := newTestWorker(&fakeClient{})
	result, err := w.handleJob(testRuntimeContext(topicRead), map[string]any{
		"action": actionWorkflowExecute,
		"params": map[string]any{"workflow_id": "wf-1"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, topicWrite) {
		t.Fatalf("expected topic error, got %+v", result)
	}
}

func TestHandleJobRejectsDisallowedWorkflow(t *testing.T) {
	client := &fakeClient{}
	w := newTestWorker(client)
	w.cfg.Profiles["default"] = config.Profile{
		Name:             "default",
		BaseURL:          "http://n8n.local",
		APIKey:           "secret",
		AllowedWorkflows: []string{"allowed-*"},
	}
	result, err := w.handleJob(testRuntimeContext(topicWrite), map[string]any{
		"action": actionWorkflowExecute,
		"params": map[string]any{"workflow_id": "blocked-1"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, "not allowed") {
		t.Fatalf("expected workflow allowlist error, got %+v", result)
	}
}

func TestHandleJobWaitsForCompletion(t *testing.T) {
	client := &fakeClient{
		executeResult: map[string]any{"executionId": "exec-1"},
		getExecutionResults: []map[string]any{
			{"id": "exec-1", "status": "running"},
			{"id": "exec-1", "status": "success", "stoppedAt": "2026-03-21T01:00:00Z"},
		},
	}
	w := newTestWorker(client)
	result, err := w.handleJob(testRuntimeContext(topicWrite), map[string]any{
		"action": actionWorkflowExecute,
		"params": map[string]any{
			"workflow_id":         "allowed-1",
			"payload":             map[string]any{"hello": "world"},
			"wait_for_completion": true,
		},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if result.StatusCode != 200 || result.ExecutionID != "exec-1" || result.Status != "success" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if client.executeWorkflowID != "allowed-1" {
		t.Fatalf("unexpected workflow id passed to client: %q", client.executeWorkflowID)
	}
	if client.getExecutionCalls < 2 {
		t.Fatalf("expected polling to occur, got %d calls", client.getExecutionCalls)
	}
}

func TestHandleJobFiltersWorkflowList(t *testing.T) {
	client := &fakeClient{listWorkflowsResult: map[string]any{
		"data": []any{
			map[string]any{"id": "allowed-1"},
			map[string]any{"id": "blocked-1"},
		},
	}}
	w := newTestWorker(client)
	w.cfg.Profiles["default"] = config.Profile{
		Name:             "default",
		BaseURL:          "http://n8n.local",
		APIKey:           "secret",
		AllowedWorkflows: []string{"allowed-*"},
	}
	result, err := w.handleJob(testRuntimeContext(topicRead), map[string]any{
		"action": actionWorkflowList,
		"params": map[string]any{},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	data, _ := result.Result.(map[string]any)
	items, _ := data["data"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected filtered workflow list, got %+v", items)
	}
}

func newTestWorker(client *fakeClient) *Worker {
	cfg := config.Config{
		RequestTimeout:      2 * time.Second,
		ExecutePollInterval: 1 * time.Millisecond,
		ExecuteWaitTimeout:  100 * time.Millisecond,
		DefaultProfile:      "default",
		Profiles: map[string]config.Profile{
			"default": {
				Name:             "default",
				BaseURL:          "http://n8n.local",
				APIKey:           "secret",
				AllowedWorkflows: []string{"allowed-*"},
			},
		},
	}
	return &Worker{
		cfg:      cfg,
		workerID: "worker-test",
		newClient: func(profile config.Profile, timeout time.Duration) (n8nClient, error) {
			return client, nil
		},
	}
}

func testRuntimeContext(topic string) runtime.Context {
	return runtime.Context{
		Job:    &agentv1.JobRequest{JobId: "job-123", Topic: topic},
		Packet: &agentv1.BusPacket{TraceId: "trace-123"},
	}
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	output := map[string]any{}
	for key, value := range input {
		output[key] = value
	}
	return output
}
