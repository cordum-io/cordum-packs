package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/n8n/internal/config"
)

type fakeStarter struct {
	workflowID     string
	payload        any
	idempotencyKey string
}

func (f *fakeStarter) StartRun(_ context.Context, workflowID string, payload any, idempotencyKey string) (string, error) {
	f.workflowID = workflowID
	f.payload = payload
	f.idempotencyKey = idempotencyKey
	return "run-123", nil
}

func TestHandlerAcceptsSignedWebhook(t *testing.T) {
	starter := &fakeStarter{}
	cfg := config.Config{
		WebhookSecret: "secret",
		WebhookWorkflowMap: map[string]string{
			"/hooks/inbound": "cordum-workflow-1",
		},
	}
	server := New(cfg, starter)
	body := []byte(`{"workflowId":"source-workflow","executionId":"exec-42","value":"ok"}`)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/hooks/inbound", bytes.NewReader(body))
	req.Header.Set(SignatureHeader, "sha256="+ComputeSignature("secret", body))
	resp := httptest.NewRecorder()

	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", resp.Code, resp.Body.String())
	}
	if starter.workflowID != "cordum-workflow-1" {
		t.Fatalf("unexpected target workflow id: %q", starter.workflowID)
	}
	payload, ok := starter.payload.(map[string]any)
	if !ok {
		t.Fatalf("expected payload map, got %#v", starter.payload)
	}
	if payload["source"] != "n8n" || payload["workflow_id"] != "source-workflow" || payload["execution_id"] != "exec-42" {
		t.Fatalf("unexpected webhook payload: %+v", payload)
	}
	if starter.idempotencyKey != "exec-42" {
		t.Fatalf("expected execution id as idempotency key, got %q", starter.idempotencyKey)
	}
}

func TestHandlerRejectsInvalidMethod(t *testing.T) {
	server := New(config.Config{WebhookWorkflowMap: map[string]string{"/hooks/inbound": "wf"}}, &fakeStarter{})
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/hooks/inbound", nil)
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.Code)
	}
}

func TestHandlerRejectsInvalidSignature(t *testing.T) {
	server := New(config.Config{
		WebhookSecret:      "secret",
		WebhookWorkflowMap: map[string]string{"/hooks/inbound": "wf"},
	}, &fakeStarter{})
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/hooks/inbound", bytes.NewReader([]byte(`{"ok":true}`)))
	req.Header.Set(SignatureHeader, "sha256=bad")
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
}

func TestBuildWebhookPayloadFallsBackToPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/hooks/inbound", bytes.NewReader([]byte(`{"message":"hello"}`)))
	payload := buildWebhookPayload("/hooks/inbound", req, []byte(`{"message":"hello"}`))
	if payload["workflow_id"] != "/hooks/inbound" {
		t.Fatalf("expected workflow_id fallback to path, got %+v", payload)
	}
	if _, ok := payload["received_at"].(string); !ok {
		t.Fatalf("expected received_at string, got %+v", payload)
	}
	if _, err := json.Marshal(payload); err != nil {
		t.Fatalf("payload should be json serializable: %v", err)
	}
}
