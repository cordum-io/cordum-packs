package mistralapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChatResponse{
			ID: "chat-1", Model: "mistral-small-latest",
			Choices: []ChatChoice{{Message: ChoiceMessage{Content: "Hi"}, FinishReason: "stop"}},
			Usage:   Usage{PromptTokens: 5, CompletionTokens: 3, TotalTokens: 8},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key")
	resp, status, err := c.ChatCompletion(context.Background(), &ChatRequest{
		Model:    "mistral-small-latest",
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Errorf("expected 200, got %d", status)
	}
	if resp.Usage.TotalTokens != 8 {
		t.Errorf("expected 8 total tokens, got %d", resp.Usage.TotalTokens)
	}
}

func TestRateLimitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		json.NewEncoder(w).Encode(map[string]string{"message": "rate limited", "type": "rate_limit"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	_, status, err := c.ChatCompletion(context.Background(), &ChatRequest{
		Model: "mistral-small-latest", Messages: []Message{{Role: "user", Content: "test"}},
	})
	if status != 429 {
		t.Errorf("expected 429, got %d", status)
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Type != "rate_limit" {
		t.Errorf("expected rate_limit, got %q", apiErr.Type)
	}
}

func TestAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"message": "invalid api key", "type": "authentication_error"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "bad-key")
	_, status, err := c.ChatCompletion(context.Background(), &ChatRequest{
		Model: "mistral-small-latest", Messages: []Message{{Role: "user", Content: "test"}},
	})
	if status != 401 {
		t.Errorf("expected 401, got %d", status)
	}
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEmbedding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("expected /v1/embeddings, got %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EmbeddingResponse{
			Model: "mistral-embed",
			Data:  []EmbeddingData{{Embedding: []float64{0.1, 0.2, 0.3}, Index: 0}},
			Usage: Usage{PromptTokens: 5, TotalTokens: 5},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	resp, _, err := c.CreateEmbedding(context.Background(), &EmbeddingRequest{
		Model: "mistral-embed", Input: "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 || len(resp.Data[0].Embedding) != 3 {
		t.Errorf("expected 1 embedding with 3 dims, got %d embeddings", len(resp.Data))
	}
}

func TestFIMCompletion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/fim/completions" {
			t.Errorf("expected /v1/fim/completions, got %q", r.URL.Path)
		}
		var req FIMRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Prompt == "" {
			t.Error("expected non-empty prompt")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(FIMResponse{
			Model:   "codestral-latest",
			Choices: []FIMChoice{{Text: "    return x + y\n", FinishReason: "stop"}},
			Usage:   Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	resp, _, err := c.FIMCompletion(context.Background(), &FIMRequest{
		Model:  "codestral-latest",
		Prompt: "def add(x, y):\n",
		Suffix: "\n\nresult = add(1, 2)",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(resp.Choices))
	}
	if resp.Choices[0].Text == "" {
		t.Error("expected non-empty FIM text")
	}
}

func TestToolCalls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ChatRequest
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.Tools) == 0 {
			t.Error("expected tools in request")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChatResponse{
			Model: "mistral-large-latest",
			Choices: []ChatChoice{{
				Message:      ChoiceMessage{Role: "assistant", ToolCalls: []map[string]any{{"function": map[string]any{"name": "search"}}}},
				FinishReason: "tool_calls",
			}},
			Usage: Usage{PromptTokens: 20, CompletionTokens: 10, TotalTokens: 30},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	resp, _, err := c.ChatCompletion(context.Background(), &ChatRequest{
		Model:    "mistral-large-latest",
		Messages: []Message{{Role: "user", Content: "search for cats"}},
		Tools:    []Tool{{Type: "function", Function: ToolFunction{Name: "search", Description: "Search"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Choices[0].FinishReason != "tool_calls" {
		t.Errorf("expected finish_reason=tool_calls, got %q", resp.Choices[0].FinishReason)
	}
}

func TestCostCalculation(t *testing.T) {
	cost := EstimateCost("mistral-large-latest", Usage{PromptTokens: 1000000, CompletionTokens: 1000000})
	if cost.InputCost != 2.0 {
		t.Errorf("expected input cost 2.0, got %f", cost.InputCost)
	}
	if cost.OutputCost != 6.0 {
		t.Errorf("expected output cost 6.0, got %f", cost.OutputCost)
	}
	if cost.Currency != "USD" {
		t.Errorf("expected USD, got %q", cost.Currency)
	}
}

func TestCostUnknownModel(t *testing.T) {
	cost := EstimateCost("unknown", Usage{PromptTokens: 100})
	if cost.TotalCost != 0 {
		t.Errorf("expected 0 cost for unknown model, got %f", cost.TotalCost)
	}
}

func TestConnectionPooling(t *testing.T) {
	c := NewClient("https://api.mistral.ai", "key")
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.MaxIdleConns != 100 {
		t.Errorf("expected MaxIdleConns=100, got %d", transport.MaxIdleConns)
	}
}
