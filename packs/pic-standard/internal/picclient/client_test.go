package picclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyToolCall_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/verify" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.ToolName != "file_write" {
			t.Errorf("expected tool_name=file_write, got %q", req.ToolName)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerifyResponse{
			Allowed: true,
			EvalMs:  42,
		})
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "file_write", map[string]any{"path": "/tmp/x"})

	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false")
	}
	if resp.Error != nil {
		t.Fatalf("expected no error, got %+v", resp.Error)
	}
	if resp.EvalMs < 0 {
		t.Fatalf("expected eval_ms >= 0, got %d", resp.EvalMs)
	}
	if resp.EvalMs == 42 {
		t.Fatalf("expected client to overwrite eval_ms, still got bridge value 42")
	}
}

func TestVerifyToolCall_Denial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerifyResponse{
			Allowed: false,
			EvalMs:  10,
			Error: &VerifyError{
				Code:    "PIC_POLICY_VIOLATION",
				Message: "tool not in allowlist",
			},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "exec", nil)

	if resp.Allowed {
		t.Fatalf("expected allowed=false")
	}
	if resp.Error == nil || resp.Error.Code != "PIC_POLICY_VIOLATION" {
		t.Fatalf("expected PIC_POLICY_VIOLATION, got %+v", resp.Error)
	}
	if resp.EvalMs == 10 {
		t.Fatalf("expected client to overwrite eval_ms, still got bridge value 10")
	}
}

func TestVerifyToolCall_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"allowed":true,"eval_ms":1}`))
	}))
	defer srv.Close()

	c := New(srv.URL, 100*time.Millisecond, "")
	resp := c.VerifyToolCall(context.Background(), "slow_tool", nil)

	if resp.Allowed {
		t.Fatalf("expected fail-closed on timeout")
	}
	if resp.Error == nil || resp.Error.Code != "PIC_BRIDGE_UNREACHABLE" {
		t.Fatalf("expected PIC_BRIDGE_UNREACHABLE, got %+v", resp.Error)
	}
}

func TestVerifyToolCall_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "some_tool", nil)

	if resp.Allowed {
		t.Fatalf("expected fail-closed on malformed JSON")
	}
	if resp.Error == nil || resp.Error.Code != "PIC_BRIDGE_UNREACHABLE" {
		t.Fatalf("expected PIC_BRIDGE_UNREACHABLE, got %+v", resp.Error)
	}
}

func TestVerifyToolCall_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "some_tool", nil)

	if resp.Allowed {
		t.Fatalf("expected fail-closed on 500")
	}
	if resp.Error == nil || resp.Error.Code != "PIC_BRIDGE_UNREACHABLE" {
		t.Fatalf("expected PIC_BRIDGE_UNREACHABLE, got %+v", resp.Error)
	}
}

func TestVerifyToolCall_Non2xxLargeBody(t *testing.T) {
	largeBody := strings.Repeat("x", 2048)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(largeBody))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "some_tool", nil)

	if resp.Allowed {
		t.Fatalf("expected fail-closed on 502")
	}
	if resp.Error == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(resp.Error.Message, "...(truncated)") {
		t.Fatalf("expected truncation marker in error message, got: %s", resp.Error.Message)
	}
	if len(resp.Error.Message) > 600 {
		t.Fatalf("expected error message to be truncated, got length %d", len(resp.Error.Message))
	}
}

func TestVerifyToolCall_EmptyToolName(t *testing.T) {
	c := New("http://localhost:9999", 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "", nil)

	if resp.Allowed {
		t.Fatalf("expected fail-closed on empty tool_name")
	}
	if resp.Error == nil || resp.Error.Code != "PIC_BRIDGE_UNREACHABLE" {
		t.Fatalf("expected PIC_BRIDGE_UNREACHABLE, got %+v", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "empty tool_name") {
		t.Fatalf("expected empty tool_name message, got: %s", resp.Error.Message)
	}
}

func TestVerifyToolCall_InconsistentResponse_AllowedFalseNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"allowed":false,"eval_ms":5}`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "some_tool", nil)

	if resp.Allowed {
		t.Fatalf("expected fail-closed")
	}
	if resp.Error == nil || resp.Error.Code != "PIC_BRIDGE_UNREACHABLE" {
		t.Fatalf("expected PIC_BRIDGE_UNREACHABLE for inconsistent response, got %+v", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "error missing") {
		t.Fatalf("expected 'error missing' message, got: %s", resp.Error.Message)
	}
}

func TestVerifyToolCall_InconsistentResponse_AllowedTrueWithError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"allowed":true,"eval_ms":5,"error":{"code":"WEIRD","message":"bug"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "some_tool", nil)

	if resp.Allowed {
		t.Fatalf("expected fail-closed on inconsistent response")
	}
	if resp.Error == nil || resp.Error.Code != "PIC_BRIDGE_UNREACHABLE" {
		t.Fatalf("expected PIC_BRIDGE_UNREACHABLE, got %+v", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "error present") {
		t.Fatalf("expected 'error present' message, got: %s", resp.Error.Message)
	}
}

func TestVerifyToolCall_Unreachable(t *testing.T) {
	c := New("http://127.0.0.1:1", 500*time.Millisecond, "")
	resp := c.VerifyToolCall(context.Background(), "some_tool", nil)

	if resp.Allowed {
		t.Fatalf("expected fail-closed on unreachable")
	}
	if resp.Error == nil || resp.Error.Code != "PIC_BRIDGE_UNREACHABLE" {
		t.Fatalf("expected PIC_BRIDGE_UNREACHABLE, got %+v", resp.Error)
	}
}

func TestHealthCheck_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/health" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("expected healthy, got %v", err)
	}
}

func TestHealthCheck_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"degraded"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	if err := c.HealthCheck(context.Background()); err == nil {
		t.Fatalf("expected error for unhealthy bridge")
	}
}

func TestHealthCheck_Unreachable(t *testing.T) {
	c := New("http://127.0.0.1:1", 500*time.Millisecond, "")
	if err := c.HealthCheck(context.Background()); err == nil {
		t.Fatalf("expected error for unreachable bridge")
	}
}

func TestNew_TrailingSlash(t *testing.T) {
	c := New("http://localhost:3100/", 5*time.Second, "")
	if c.baseURL != "http://localhost:3100" {
		t.Fatalf("expected trailing slash stripped, got %q", c.baseURL)
	}
}

func TestVerifyToolCall_WithAuthToken(t *testing.T) {
	headerChecked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token-123" {
			t.Errorf("expected Authorization: Bearer test-token-123, got %q", auth)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		headerChecked = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerifyResponse{Allowed: true})
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "test-token-123")
	resp := c.VerifyToolCall(context.Background(), "file_write", nil)

	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false")
	}
	if !headerChecked {
		t.Fatalf("auth header was never checked by server")
	}
}

func TestVerifyToolCall_NoAuthToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("expected no Authorization header, got %q", auth)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerifyResponse{Allowed: true})
	}))
	defer srv.Close()

	c := New(srv.URL, 5*time.Second, "")
	resp := c.VerifyToolCall(context.Background(), "file_write", nil)

	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false")
	}
}
