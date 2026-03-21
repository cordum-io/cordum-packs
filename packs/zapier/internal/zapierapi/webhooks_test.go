package zapierapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookSendPostsJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/hook" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if payload["hello"] != "world" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"accepted":true}`)
	}))
	defer server.Close()

	client := NewWebhookClient(map[string]string{"marketing": server.URL + "/hook"}, time.Second)
	result, err := client.Send(context.Background(), "Marketing", map[string]any{"hello": "world"})
	if err != nil {
		t.Fatalf("Send error = %v", err)
	}
	if result.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected status code: %+v", result)
	}
	body, _ := result.Body.(map[string]any)
	if body["accepted"] != true {
		t.Fatalf("unexpected body: %+v", result.Body)
	}
}

func TestWebhookSendHandlesTextResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	client := NewWebhookClient(map[string]string{"status": server.URL}, time.Second)
	result, err := client.Send(context.Background(), "status", map[string]any{})
	if err != nil {
		t.Fatalf("Send error = %v", err)
	}
	if result.Body != "ok" {
		t.Fatalf("unexpected body: %+v", result.Body)
	}
}

func TestWebhookSendRejectsUnknownAlias(t *testing.T) {
	client := NewWebhookClient(map[string]string{}, time.Second)
	if _, err := client.Send(context.Background(), "missing", map[string]any{}); err == nil {
		t.Fatal("expected missing alias error")
	}
}
