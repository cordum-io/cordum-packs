package otelapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClientDoOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected bearer header, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "ua" {
			t.Fatalf("expected user agent, got %q", got)
		}
		if got := r.URL.Query().Get("service"); got != "api" {
			t.Fatalf("expected query param, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-123")
		_, _ = w.Write([]byte(`{"data": []}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token", Options{UserAgent: "ua"})
	query := url.Values{"service": []string{"api"}}
	resp, err := client.Do(context.Background(), http.MethodGet, "/traces", query, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RequestID != "req-123" {
		t.Fatalf("expected request id, got %q", resp.RequestID)
	}
}

func TestClientDoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad query"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token", Options{})
	_, err := client.Do(context.Background(), http.MethodGet, "/traces", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "opentelemetry api error (400): bad query" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientDoRejectsAbsoluteEndpointPath(t *testing.T) {
	client := NewClient("https://jaeger.example/api", "token", Options{})
	_, err := client.Do(context.Background(), http.MethodGet, "https://evil.example/traces", nil, nil)
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "relative") {
		t.Fatalf("expected relative path validation error, got %v", err)
	}
}

func TestClientDoPreservesBasePathPrefix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/api/traces" {
			t.Fatalf("expected /api/traces, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := NewClient(server.URL+"/api", "token", Options{})
	if _, err := client.Do(context.Background(), http.MethodGet, "/traces", nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
