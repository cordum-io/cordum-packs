package gitlabapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDoPrivateToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("PRIVATE-TOKEN"); got != "token" {
			t.Fatalf("expected private token header, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "ua" {
			t.Fatalf("expected user agent, got %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("expected accept header, got %q", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "5" {
			t.Fatalf("expected query param, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-123")
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token", Options{UserAgent: "ua"})
	query := url.Values{"per_page": []string{"5"}}
	resp, err := client.Do(context.Background(), http.MethodGet, "/projects", query, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RequestID != "req-123" {
		t.Fatalf("expected request id, got %q", resp.RequestID)
	}
}

func TestClientDoBearerTokenError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected bearer token header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"nope"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token", Options{TokenType: "bearer"})
	_, err := client.Do(context.Background(), http.MethodGet, "/projects", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "gitlab api error (401): nope" {
		t.Fatalf("unexpected error: %v", err)
	}
}
