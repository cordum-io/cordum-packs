package zapierapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListActionsUsesConfiguredHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/ai-actions/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get(apiKeyHeader); got != "secret" {
			t.Fatalf("unexpected x-api-key: %q", got)
		}
		if got := r.Header.Get(authHeader); got != "Bearer secret" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.URL.Query().Get("app"); got != "gmail" {
			t.Fatalf("unexpected app query: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"results":[{"id":"act-1"}]}`)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatalf("NewClient error = %v", err)
	}
	result, err := client.ListActions(context.Background(), map[string]any{"app": "gmail", "limit": 10})
	if err != nil {
		t.Fatalf("ListActions error = %v", err)
	}
	results, _ := result["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected one result, got %+v", result)
	}
}

func TestExecuteActionUsesStoredActionEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/v2/ai-actions/action-123/execute/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if payload["instructions"] != "send an invoice" {
			t.Fatalf("unexpected instructions: %+v", payload)
		}
		if payload["preview_only"] != true {
			t.Fatalf("expected preview_only true, got %+v", payload)
		}
		_, _ = io.WriteString(w, `{"execution_log_id":"log-1","action_used":"gmail send email","status":"preview"}`)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatalf("NewClient error = %v", err)
	}
	result, err := client.ExecuteAction(context.Background(), ExecuteRequest{
		ActionID:     "action-123",
		Instructions: "send an invoice",
		PreviewOnly:  true,
		ParamsHints:  map[string]any{"to": "ops@example.com"},
	})
	if err != nil {
		t.Fatalf("ExecuteAction error = %v", err)
	}
	if got := result["execution_log_id"]; got != "log-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got := result["action_id"]; got != "action-123" {
		t.Fatalf("expected echoed action_id, got %+v", result)
	}
}

func TestExecuteActionFallsBackToGenericEndpointWithoutActionID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/execute/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"execution_log_id":"log-2","action_used":"calendar create event","status":"success"}`)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatalf("NewClient error = %v", err)
	}
	result, err := client.ExecuteAction(context.Background(), ExecuteRequest{Instructions: "schedule tomorrow's sync"})
	if err != nil {
		t.Fatalf("ExecuteAction error = %v", err)
	}
	if got := result["execution_log_id"]; got != "log-2" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestGetExecutionLog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/execute/log/log-123/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"execution_log_id":"log-123","status":"success"}`)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatalf("NewClient error = %v", err)
	}
	result, err := client.GetExecutionLog(context.Background(), "log-123")
	if err != nil {
		t.Fatalf("GetExecutionLog error = %v", err)
	}
	if got := result["execution_log_id"]; got != "log-123" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
