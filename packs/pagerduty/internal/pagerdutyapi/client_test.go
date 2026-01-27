package pagerdutyapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDoGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token token=token" {
			t.Fatalf("expected auth header, got %q", got)
		}
		if got := r.Header.Get("Accept"); got != acceptHeader {
			t.Fatalf("expected accept header, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "ua" {
			t.Fatalf("expected user agent, got %q", got)
		}
		if got := r.Header.Get("From"); got != "user@example.com" {
			t.Fatalf("expected From header, got %q", got)
		}
		if got := r.URL.Query().Get("statuses[]"); got != "triggered" {
			t.Fatalf("expected query value, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{Token: "token", UserAgent: "ua"})
	query := url.Values{}
	query.Add("statuses[]", "triggered")
	result, status, err := client.Do(context.Background(), http.MethodGet, "/incidents", query, nil, map[string]string{"From": "user@example.com"})
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
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{})
	_, _, err := client.Do(context.Background(), http.MethodGet, "/incidents", nil, nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "pagerduty error: bad request" {
		t.Fatalf("unexpected error: %v", err)
	}
}
