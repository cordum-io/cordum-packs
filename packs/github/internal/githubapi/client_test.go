package githubapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDoOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected auth header, got %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Fatalf("expected accept header, got %q", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
			t.Fatalf("expected api version, got %q", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "5" {
			t.Fatalf("expected query param, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-GitHub-Request-Id", "req-123")
		w.Header().Set("X-RateLimit-Limit", "5000")
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, StaticTokenProvider{TokenValue: "token"}, Options{})
	query := url.Values{"per_page": []string{"5"}}
	resp, err := client.Do(context.Background(), http.MethodGet, "/repos/org/repo", query, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.RequestID != "req-123" {
		t.Fatalf("expected request id, got %q", resp.RequestID)
	}
	if resp.RateLimit["limit"] != "5000" {
		t.Fatalf("expected rate limit header")
	}
}

func TestClientDoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, StaticTokenProvider{TokenValue: "token"}, Options{})
	_, err := client.Do(context.Background(), http.MethodGet, "/repos/org/repo", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "github api error (404): not found" {
		t.Fatalf("unexpected error: %v", err)
	}
}
