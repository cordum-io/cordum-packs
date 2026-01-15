package msteamsapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDoBearerOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("expected bearer header, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "ua" {
			t.Fatalf("expected user agent, got %q", got)
		}
		if got := r.URL.Query().Get("$top"); got != "5" {
			t.Fatalf("expected query param, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", "req-123")
		_, _ = w.Write([]byte(`{"value": []}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token", Options{UserAgent: "ua"})
	query := url.Values{"$top": []string{"5"}}
	resp, err := client.Do(context.Background(), http.MethodGet, "/me/joinedTeams", query, nil)
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
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken","message":"Access token is empty"}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token", Options{})
	_, err := client.Do(context.Background(), http.MethodGet, "/me/joinedTeams", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "msteams api error (401): InvalidAuthenticationToken: Access token is empty" {
		t.Fatalf("unexpected error: %v", err)
	}
}
