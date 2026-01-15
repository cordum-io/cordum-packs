package vaultapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientDoOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "token" {
			t.Fatalf("expected vault token header, got %q", got)
		}
		if got := r.Header.Get("X-Vault-Namespace"); got != "team" {
			t.Fatalf("expected namespace header, got %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "ua" {
			t.Fatalf("expected user agent, got %q", got)
		}
		if got := r.URL.Query().Get("list"); got != "true" {
			t.Fatalf("expected query param, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Vault-Request", "req-123")
		_, _ = w.Write([]byte(`{"data":{"keys":["one"]}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token", Options{UserAgent: "ua", Namespace: "team"})
	query := url.Values{"list": []string{"true"}}
	resp, err := client.Do(context.Background(), http.MethodGet, "/secret", query, nil)
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
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token", Options{})
	_, err := client.Do(context.Background(), http.MethodGet, "/secret", nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "vault api error (403): permission denied" {
		t.Fatalf("unexpected error: %v", err)
	}
}
