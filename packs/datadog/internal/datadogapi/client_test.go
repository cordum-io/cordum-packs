package datadogapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDoGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("DD-API-KEY"); got != "api" {
			t.Fatalf("expected api key, got %q", got)
		}
		if got := r.Header.Get("DD-APPLICATION-KEY"); got != "app" {
			t.Fatalf("expected app key, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "ua" {
			t.Fatalf("expected user agent, got %q", got)
		}
		if got := r.URL.Query().Get("from"); got != "1" {
			t.Fatalf("expected from query, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{APIKey: "api", AppKey: "app", UserAgent: "ua"})
	result, status, err := client.Do(context.Background(), http.MethodGet, "/api/v1/query", url.Values{"from": []string{"1"}}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}
	payload, ok := result.(map[string]any)
	if !ok || payload["ok"] != true {
		t.Fatalf("expected payload ok=true")
	}
}

func TestClientDoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["bad request"]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{})
	_, _, err := client.Do(context.Background(), http.MethodGet, "/api/v1/query", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "datadog error: bad request" {
		t.Fatalf("unexpected error: %v", err)
	}
}
