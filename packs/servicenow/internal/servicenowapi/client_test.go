package servicenowapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDoGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected bearer token, got %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("expected accept header, got %q", got)
		}
		if got := r.URL.Query().Get("sysparm_limit"); got != "10" {
			t.Fatalf("expected query value, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"ok":true}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{Token: "token"})
	query := url.Values{"sysparm_limit": []string{"10"}}
	result, status, err := client.Do(context.Background(), http.MethodGet, "/api/now/table/incident", query, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}
	payload, ok := result.(map[string]any)
	if !ok || payload["result"] == nil {
		t.Fatalf("expected result payload")
	}
}

func TestClientDoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad request"}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{})
	_, _, err := client.Do(context.Background(), http.MethodGet, "/api/now/table/incident", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "servicenow error: bad request" {
		t.Fatalf("unexpected error: %v", err)
	}
}
