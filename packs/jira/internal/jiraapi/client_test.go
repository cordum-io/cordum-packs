package jiraapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDoOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Basic token" {
			t.Fatalf("expected auth header, got %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("expected accept header, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "ua" {
			t.Fatalf("expected user agent, got %q", got)
		}
		if got := r.URL.Query().Get("maxResults"); got != "5" {
			t.Fatalf("expected query param, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req-123")
		_, _ = w.Write([]byte(`{"issues":[]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "Basic token", Options{UserAgent: "ua"})
	query := url.Values{"maxResults": []string{"5"}}
	resp, err := client.Do(context.Background(), http.MethodGet, "/rest/api/3/search", query, nil)
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
		_, _ = w.Write([]byte(`{"errorMessages":["bad request"]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "Basic token", Options{})
	_, err := client.Do(context.Background(), http.MethodGet, "/rest/api/3/search", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "jira api error (400): bad request" {
		t.Fatalf("unexpected error: %v", err)
	}
}
