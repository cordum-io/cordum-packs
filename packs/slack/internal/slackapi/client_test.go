package slackapi

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
		if got := r.Header.Get("User-Agent"); got != "ua" {
			t.Fatalf("expected user agent, got %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Fatalf("expected content type, got %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "10" {
			t.Fatalf("expected query limit, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok": true, "data": {"message": "hi"}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, StaticTokenProvider{TokenValue: "token"}, Options{UserAgent: "ua"})
	query := url.Values{"limit": []string{"10"}}
	resp, err := client.Do(context.Background(), http.MethodPost, "/chat.postMessage", query, map[string]any{"text": "hi"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok response")
	}
}

func TestClientDoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok": false, "error": "not_authed"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, StaticTokenProvider{TokenValue: "token"}, Options{})
	_, err := client.Do(context.Background(), http.MethodGet, "/auth.test", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "slack api error (200): not_authed" {
		t.Fatalf("unexpected error: %v", err)
	}
}
