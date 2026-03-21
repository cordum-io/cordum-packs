package n8napi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientNormalizesBaseURL(t *testing.T) {
	t.Parallel()

	client, err := NewClient("http://localhost:5678", "secret", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if client.baseURL != "http://localhost:5678/api/v1" {
		t.Fatalf("unexpected base URL: %q", client.baseURL)
	}
}

func TestListWorkflowsUsesAPIKeyHeaderAndQuery(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/workflows" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get(apiKeyHeader) != "secret" {
			t.Fatalf("missing api key header")
		}
		if got := r.URL.Query().Get("limit"); got != "25" {
			t.Fatalf("unexpected limit query: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "secret", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if _, err := client.ListWorkflows(context.Background(), map[string]any{"limit": 25}); err != nil {
		t.Fatalf("ListWorkflows returned error: %v", err)
	}
}

func TestExecuteWorkflowFallsBackToRunEndpoint(t *testing.T) {
	t.Parallel()

	calls := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/workflows/123/execute":
			http.Error(w, "not found", http.StatusNotFound)
		case "/api/v1/workflows/123/run":
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "hello") {
				t.Fatalf("expected payload passthrough body, got %s", string(body))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"executionId":"exec-1"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "secret", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	resp, err := client.ExecuteWorkflow(context.Background(), "123", map[string]any{"message": "hello"})
	if err != nil {
		t.Fatalf("ExecuteWorkflow returned error: %v", err)
	}
	if resp["executionId"] != "exec-1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(calls) != 2 {
		t.Fatalf("expected two execution attempts, got %v", calls)
	}
}

func TestActivateWorkflowUsesPost(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/v1/workflows/123/activate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"123","active":true}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "secret", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	resp, err := client.ActivateWorkflow(context.Background(), "123")
	if err != nil {
		t.Fatalf("ActivateWorkflow returned error: %v", err)
	}
	if active, _ := resp["active"].(bool); !active {
		t.Fatalf("expected active=true, got %+v", resp)
	}
}

func TestDoJSONReturnsAPIError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "secret", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	_, err = client.ListCredentials(context.Background())
	apiErr := &APIError{}
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected APIError, got %v", err)
	}
	if !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("expected APIError body, got %v", err)
	}
	_ = apiErr
}

func TestExecuteWorkflowEncodesJSONBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if payload["value"] != "ok" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL+"/api/v1", "secret", 5*time.Second)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if _, err := client.ExecuteWorkflow(context.Background(), "abc", map[string]any{"value": "ok"}); err != nil {
		t.Fatalf("ExecuteWorkflow returned error: %v", err)
	}
}
