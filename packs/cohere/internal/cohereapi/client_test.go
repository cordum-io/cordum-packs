package cohereapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("expected Bearer test-key, got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChatResponse{Text: "Hi", FinishReason: "COMPLETE"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key")
	resp, _, err := c.Chat(context.Background(), &ChatRequest{Message: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "Hi" {
		t.Errorf("expected 'Hi', got %q", resp.Text)
	}
}

func TestChatWithBilledUnits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChatResponse{
			Text:         "Answer",
			FinishReason: "COMPLETE",
			Meta: &Meta{
				BilledUnits: &BilledUnits{InputTokens: 10, OutputTokens: 5},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	resp, _, err := c.Chat(context.Background(), &ChatRequest{Model: "command-r-plus", Message: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Meta == nil || resp.Meta.BilledUnits == nil {
		t.Fatal("expected billed_units in meta")
	}
	if resp.Meta.BilledUnits.InputTokens != 10 {
		t.Errorf("expected 10 input tokens, got %f", resp.Meta.BilledUnits.InputTokens)
	}
}

func TestEmbed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embed" {
			t.Errorf("expected /v1/embed, got %q", r.URL.Path)
		}
		var req EmbedRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.InputType == "" {
			t.Error("expected input_type to be set")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EmbedResponse{
			Embeddings: [][]float64{{0.1, 0.2}, {0.3, 0.4}},
			Meta:       &Meta{BilledUnits: &BilledUnits{InputTokens: 5}},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	resp, _, err := c.Embed(context.Background(), &EmbedRequest{
		Model:     "embed-english-v3.0",
		Texts:     []string{"hello", "world"},
		InputType: "search_document",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Embeddings == nil {
		t.Error("expected embeddings")
	}
}

func TestRerank(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/rerank" {
			t.Errorf("expected /v1/rerank, got %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RerankResponse{
			Results: []RerankResult{
				{Index: 0, RelevanceScore: 0.95},
				{Index: 2, RelevanceScore: 0.80},
			},
			Meta: &Meta{BilledUnits: &BilledUnits{SearchUnits: 1}},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	resp, _, err := c.Rerank(context.Background(), &RerankRequest{
		Query:     "python",
		Documents: []string{"python is great", "java is fine", "python rocks"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(resp.Results))
	}
	if resp.Results[0].RelevanceScore < 0.9 {
		t.Errorf("expected high relevance, got %f", resp.Results[0].RelevanceScore)
	}
}

func TestClassify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/classify" {
			t.Errorf("expected /v1/classify, got %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ClassifyResponse{
			Classifications: []ClassifyResult{
				{Input: "great product", Prediction: "positive", Confidence: 0.92},
			},
			Meta: &Meta{BilledUnits: &BilledUnits{Classifications: 1}},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	resp, _, err := c.Classify(context.Background(), &ClassifyRequest{
		Inputs: []string{"great product"},
		Examples: []ClassifyExample{
			{Text: "awesome", Label: "positive"},
			{Text: "terrible", Label: "negative"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Classifications) != 1 {
		t.Fatalf("expected 1 classification, got %d", len(resp.Classifications))
	}
	if resp.Classifications[0].Prediction != "positive" {
		t.Errorf("expected positive, got %q", resp.Classifications[0].Prediction)
	}
}

func TestAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"message": "invalid api key"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "bad")
	_, status, err := c.Chat(context.Background(), &ChatRequest{Message: "test"})
	if status != 401 {
		t.Errorf("expected 401, got %d", status)
	}
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRateLimitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		json.NewEncoder(w).Encode(map[string]string{"message": "rate limited"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key")
	_, status, err := c.Chat(context.Background(), &ChatRequest{Message: "test"})
	if status != 429 {
		t.Errorf("expected 429, got %d", status)
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Message != "rate limited" {
		t.Errorf("expected 'rate limited', got %q", apiErr.Message)
	}
}

func TestConnectionPooling(t *testing.T) {
	c := NewClient("https://api.cohere.com", "key")
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.MaxIdleConns != 100 {
		t.Errorf("expected 100, got %d", transport.MaxIdleConns)
	}
}
