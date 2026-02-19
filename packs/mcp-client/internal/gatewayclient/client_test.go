package gatewayclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetMemoryOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/memory" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("ptr"); got != "mem://ptr" {
			t.Fatalf("expected ptr query, got %q", got)
		}
		if got := r.Header.Get("X-API-Key"); got != "key" {
			t.Fatalf("expected API key header, got %q", got)
		}
		if got := r.Header.Get("X-Tenant-ID"); got != "tenant-a" {
			t.Fatalf("expected tenant header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pointer":"mem://ptr","json":{"ok":true}}`))
	}))
	defer server.Close()

	client := New(server.URL, "key", "tenant-a")
	resp, err := client.GetMemory(context.Background(), "mem://ptr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.Pointer != "mem://ptr" {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestDoJSONRejectsAbsolutePath(t *testing.T) {
	client := New("https://gateway.example", "", "")
	err := client.doJSON(context.Background(), http.MethodGet, "https://evil.example/memory", nil, nil)
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "relative") {
		t.Fatalf("expected relative path validation error, got %v", err)
	}
}
