package mcpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHTTPClientRejectsUnsupportedScheme(t *testing.T) {
	_, err := newHTTPClient(Server{URL: "ftp://example.com/rpc"})
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPClientRequestOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/rpc" {
			t.Fatalf("expected /rpc, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("expected json content type, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer server.Close()

	client, err := newHTTPClient(Server{URL: server.URL + "/rpc"})
	if err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}

	resp, err := client.Request(context.Background(), "tools/list", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected request error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response")
	}
}
