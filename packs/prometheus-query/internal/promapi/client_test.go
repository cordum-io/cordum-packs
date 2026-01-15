package promapi

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
		if got := r.URL.Query().Get("query"); got != "up" {
			t.Fatalf("expected query param, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{Bearer: "token", UserAgent: "ua"})
	query := url.Values{"query": []string{"up"}}
	resp, _, err := client.Do(context.Background(), http.MethodGet, "/api/v1/query", query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "success" {
		t.Fatalf("expected success status")
	}
}

func TestClientDoBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "alice" || pass != "secret" {
			t.Fatalf("expected basic auth, got %q/%q", user, pass)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{BasicUser: "alice", BasicPass: "secret"})
	_, _, err := client.Do(context.Background(), http.MethodGet, "/api/v1/alerts", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientDoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"bad query"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, Options{})
	_, _, err := client.Do(context.Background(), http.MethodGet, "/api/v1/query", nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != "bad query" {
		t.Fatalf("unexpected error: %v", err)
	}
}
