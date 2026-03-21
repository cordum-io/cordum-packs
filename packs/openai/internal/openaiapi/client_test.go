package openaiapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestChatCompletionSetsHeadersAndParsesRateLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("authorization header = %q", got)
		}
		if got := r.Header.Get("OpenAI-Organization"); got != "org-123" {
			t.Fatalf("organization header = %q", got)
		}
		w.Header().Set("x-request-id", "req-123")
		w.Header().Set("x-ratelimit-limit-requests", "5000")
		w.Header().Set("x-ratelimit-remaining-requests", "4999")
		w.Header().Set("x-ratelimit-reset-requests", "1m")
		w.Header().Set("x-ratelimit-limit-tokens", "1000000")
		w.Header().Set("x-ratelimit-remaining-tokens", "999000")
		w.Header().Set("x-ratelimit-reset-tokens", "1m")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"chatcmpl_1","model":"gpt-4o","usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", Options{
		Organization:     "org-123",
		Timeout:          5 * time.Second,
		MaxRetries:       0,
		RetryOnRateLimit: true,
	})
	temp := 0.2
	resp, err := client.ChatCompletion(context.Background(), ChatCompletionRequest{
		Model:       "gpt-4o",
		Messages:    []map[string]any{{"role": "user", "content": "hello"}},
		Temperature: &temp,
		MaxTokens:   64,
	})
	if err != nil {
		t.Fatalf("ChatCompletion error = %v", err)
	}

	if resp.RequestID != "req-123" {
		t.Fatalf("request id = %q", resp.RequestID)
	}
	if resp.Usage.TotalTokens != 20 {
		t.Fatalf("total tokens = %d", resp.Usage.TotalTokens)
	}
	if resp.RateLimit.RemainingRequests != 4999 || resp.RateLimit.RemainingTokens != 999000 {
		t.Fatalf("unexpected rate limit: %+v", resp.RateLimit)
	}
}

func TestClientRetries429(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0.001")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"message":"slow down","type":"rate_limit_error"}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"data":[{"embedding":[0.1,0.2]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":4,"completion_tokens":0,"total_tokens":4}}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", Options{
		Timeout:          5 * time.Second,
		MaxRetries:       1,
		RetryOnRateLimit: true,
	})
	resp, err := client.CreateEmbedding(context.Background(), EmbeddingRequest{
		Model: "text-embedding-3-small",
		Input: "hello world",
	})
	if err != nil {
		t.Fatalf("CreateEmbedding error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
	if resp.Usage.TotalTokens != 4 {
		t.Fatalf("total tokens = %d", resp.Usage.TotalTokens)
	}
}

func TestClientDoesNotRetry401(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"bad api key","type":"invalid_request_error","code":"invalid_api_key"}}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-key", Options{
		Timeout:          5 * time.Second,
		MaxRetries:       2,
		RetryOnRateLimit: true,
	})
	_, err := client.ChatCompletion(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4o",
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status code = %d", apiErr.StatusCode)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestClientReturns400Details(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"bad prompt","type":"invalid_request_error","param":"messages","code":"bad_request"}}`)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-key", Options{Timeout: 5 * time.Second})
	_, err := client.ChatCompletion(context.Background(), ChatCompletionRequest{
		Model:    "gpt-4o",
		Messages: []map[string]any{{"role": "user", "content": "hi"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad prompt") || !strings.Contains(err.Error(), "invalid_request_error") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEstimateCostUSD(t *testing.T) {
	t.Parallel()

	got := EstimateCostUSD("gpt-4o", Usage{PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500})
	if got <= 0 {
		t.Fatalf("expected positive cost, got %f", got)
	}
	embedCost := EstimateCostUSD("text-embedding-3-small", Usage{PromptTokens: 1000, TotalTokens: 1000})
	if embedCost <= 0 || embedCost >= got {
		t.Fatalf("unexpected embedding cost %f vs chat cost %f", embedCost, got)
	}
}

func TestParseChatCompletionStream(t *testing.T) {
	t.Parallel()

	stream := strings.NewReader(strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Hel"},"finish_reason":null}]}`,
		"",
		`data: {"choices":[{"delta":{"content":"lo"},"finish_reason":"stop"}]}`,
		"",
		`data: {"choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
		"",
		`data: [DONE]`,
		"",
	}, "\n"))

	transcript, err := ParseChatCompletionStream(stream, nil)
	if err != nil {
		t.Fatalf("ParseChatCompletionStream error = %v", err)
	}
	if transcript.Content != "Hello" {
		t.Fatalf("content = %q", transcript.Content)
	}
	if transcript.FinishReason != "stop" {
		t.Fatalf("finish reason = %q", transcript.FinishReason)
	}
	if transcript.Usage.TotalTokens != 7 {
		t.Fatalf("total tokens = %d", transcript.Usage.TotalTokens)
	}
	if len(transcript.Events) != 3 {
		t.Fatalf("events = %d", len(transcript.Events))
	}
}
