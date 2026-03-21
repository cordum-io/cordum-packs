package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"

	"github.com/cordum-io/cordum-packs/packs/zapier/internal/config"
	"github.com/cordum-io/cordum-packs/packs/zapier/internal/zapierapi"
)

type fakeNLAClient struct {
	listActionsResult map[string]any
	executeResult     map[string]any
	logResult         map[string]any
	lastExecute       zapierapi.ExecuteRequest
}

func (f *fakeNLAClient) ListActions(_ context.Context, _ map[string]any) (map[string]any, error) {
	return cloneMap(f.listActionsResult), nil
}

func (f *fakeNLAClient) ExecuteAction(_ context.Context, req zapierapi.ExecuteRequest) (map[string]any, error) {
	f.lastExecute = req
	return cloneMap(f.executeResult), nil
}

func (f *fakeNLAClient) GetExecutionLog(_ context.Context, _ string) (map[string]any, error) {
	return cloneMap(f.logResult), nil
}

type fakeWebhookClient struct {
	response    zapierapi.WebhookResponse
	lastName    string
	lastPayload map[string]any
}

func (f *fakeWebhookClient) Send(_ context.Context, name string, payload map[string]any) (zapierapi.WebhookResponse, error) {
	f.lastName = name
	f.lastPayload = payload
	return f.response, nil
}

func TestActionSpecs(t *testing.T) {
	expected := []string{actionNLAList, actionNLAExecute, actionNLAPreview, actionNLALog, actionWebhookSend}
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
	w := newTestWorker(&fakeNLAClient{}, &fakeWebhookClient{})
	result, err := w.handleJob(testRuntimeContext(topicRead), map[string]any{
		"action": actionNLAExecute,
		"params": map[string]any{"instruction": "send it", "action_id": "allowed-1"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, topicWrite) {
		t.Fatalf("expected topic error, got %+v", result)
	}
}

func TestHandleJobRequiresNLAKey(t *testing.T) {
	w := newTestWorker(&fakeNLAClient{}, &fakeWebhookClient{})
	w.cfg.NLAAPIKey = ""
	result, err := w.handleJob(testRuntimeContext(topicWrite), map[string]any{
		"action": actionNLAExecute,
		"params": map[string]any{"instruction": "send it"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, "NLA API key not configured") {
		t.Fatalf("expected missing key error, got %+v", result)
	}
}

func TestHandleJobRequiresActionIDWhenRulesConfigured(t *testing.T) {
	w := newTestWorker(&fakeNLAClient{}, &fakeWebhookClient{})
	w.cfg.AllowedActions = []string{"allowed-*"}
	result, err := w.handleJob(testRuntimeContext(topicWrite), map[string]any{
		"action": actionNLAExecute,
		"params": map[string]any{"instruction": "send it"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, "action_id is required") {
		t.Fatalf("expected pinned action error, got %+v", result)
	}
}

func TestHandleJobRejectsDisallowedActionID(t *testing.T) {
	w := newTestWorker(&fakeNLAClient{}, &fakeWebhookClient{})
	w.cfg.AllowedActions = []string{"allowed-*"}
	result, err := w.handleJob(testRuntimeContext(topicWrite), map[string]any{
		"action": actionNLAExecute,
		"params": map[string]any{"instruction": "send it", "action_id": "blocked-1"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, "not allowed") {
		t.Fatalf("expected allowlist error, got %+v", result)
	}
}

func TestHandleJobPreviewForcesPreviewOnly(t *testing.T) {
	client := &fakeNLAClient{executeResult: map[string]any{"execution_log_id": "log-1", "status": "preview"}}
	w := newTestWorker(client, &fakeWebhookClient{})
	result, err := w.handleJob(testRuntimeContext(topicWrite), map[string]any{
		"action": actionNLAPreview,
		"params": map[string]any{"instruction": "draft the email", "action_id": "allowed-1"},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !client.lastExecute.PreviewOnly {
		t.Fatal("expected preview_only to be true")
	}
	if result.ExecutionLogID != "log-1" || result.Status != "preview" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestHandleJobWebhookUsesAliasWithoutNLAKey(t *testing.T) {
	webhook := &fakeWebhookClient{response: zapierapi.WebhookResponse{Alias: "orders", StatusCode: 202, Body: map[string]any{"queued": true}}}
	w := newTestWorker(&fakeNLAClient{}, webhook)
	w.cfg.NLAAPIKey = ""
	result, err := w.handleJob(testRuntimeContext(topicRead), map[string]any{
		"action": actionWebhookSend,
		"params": map[string]any{"webhook_name": "orders", "payload": map[string]any{"order_id": 42}},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if webhook.lastName != "orders" {
		t.Fatalf("unexpected alias: %q", webhook.lastName)
	}
	if result.StatusCode != 202 || result.Status != "success" {
		t.Fatalf("unexpected webhook result: %+v", result)
	}
}

func TestHandleJobFiltersListResults(t *testing.T) {
	client := &fakeNLAClient{listActionsResult: map[string]any{
		"results": []any{
			map[string]any{"id": "allowed-1"},
			map[string]any{"id": "blocked-1"},
		},
	}}
	w := newTestWorker(client, &fakeWebhookClient{})
	w.cfg.AllowedActions = []string{"allowed-*"}
	result, err := w.handleJob(testRuntimeContext(topicRead), map[string]any{
		"action": actionNLAList,
		"params": map[string]any{},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	data, _ := result.Result.(map[string]any)
	items, _ := data["results"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected filtered list, got %+v", items)
	}
}

func newTestWorker(nla *fakeNLAClient, webhook *fakeWebhookClient) *Worker {
	cfg := config.Config{
		RequestTimeout: 2 * time.Second,
		NLABaseURL:     "https://actions.zapier.com/api/v2",
		NLAAPIKey:      "secret",
		WebhookURLs: map[string]string{
			"orders": "https://hooks.zapier.com/hooks/catch/123/orders",
		},
	}
	return &Worker{
		cfg:      cfg,
		workerID: "worker-test",
		newNLAClient: func(timeout time.Duration) (nlaClient, error) {
			return nla, nil
		},
		newWebhookClient: func(timeout time.Duration) webhookClient {
			return webhook
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
