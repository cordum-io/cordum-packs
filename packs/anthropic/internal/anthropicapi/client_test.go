package anthropicapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestXAPIKeyAuth verifies the client uses x-api-key header, not Bearer.
func TestXAPIKeyAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("x-api-key")
		if apiKey != "test-key-123" {
			t.Errorf("expected x-api-key=test-key-123, got %q", apiKey)
		}

		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("expected no Authorization header, got %q", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", "req-abc")
		json.NewEncoder(w).Encode(MessagesResponse{
			ID:         "msg-1",
			Type:       "message",
			Role:       "assistant",
			Content:    []ContentBlock{{Type: "text", Text: "Hello"}},
			Model:      "claude-sonnet-4-6",
			StopReason: "end_turn",
			Usage:      Usage{InputTokens: 10, OutputTokens: 5},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-key-123", "2023-06-01")
	resp, status, requestID, err := c.CreateMessage(context.Background(), &MessagesRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 100,
		Messages:  []Message{{Role: "user", Content: "Hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 200 {
		t.Errorf("expected status 200, got %d", status)
	}
	if requestID != "req-abc" {
		t.Errorf("expected request-id=req-abc, got %q", requestID)
	}
	if resp.StopReason != "end_turn" {
		t.Errorf("expected stop_reason=end_turn, got %q", resp.StopReason)
	}
}

// TestAnthropicVersionHeader verifies the anthropic-version header is set.
func TestAnthropicVersionHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := r.Header.Get("anthropic-version")
		if version != "2023-06-01" {
			t.Errorf("expected anthropic-version=2023-06-01, got %q", version)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MessagesResponse{
			ID:    "msg-1",
			Type:  "message",
			Usage: Usage{InputTokens: 5, OutputTokens: 3},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	_, _, _, err := c.CreateMessage(context.Background(), &MessagesRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 100,
		Messages:  []Message{{Role: "user", Content: "test"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSSEStreamParsing tests the SSE stream reader with a multi-event mock.
func TestSSEStreamParsing(t *testing.T) {
	ssePayload := `event: message_start
data: {"type":"message_start","message":{"id":"msg-1","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}

event: message_stop
data: {"type":"message_stop"}

`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify stream=true was sent in the request body
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		if stream, ok := req["stream"].(bool); !ok || !stream {
			t.Errorf("expected stream=true in request body")
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("request-id", "req-stream")
		w.WriteHeader(200)
		w.Write([]byte(ssePayload))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	reader, status, requestID, err := c.CreateMessageStream(context.Background(), &MessagesRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 100,
		Messages:  []Message{{Role: "user", Content: "Hi"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer reader.Close()

	if status != 200 {
		t.Errorf("expected status 200, got %d", status)
	}
	if requestID != "req-stream" {
		t.Errorf("expected request-id=req-stream, got %q", requestID)
	}

	expectedTypes := []string{
		"message_start",
		"content_block_start",
		"content_block_delta",
		"content_block_delta",
		"content_block_stop",
		"message_delta",
		"message_stop",
	}

	for i, expected := range expectedTypes {
		evt, err := reader.Next()
		if err != nil {
			t.Fatalf("event %d: unexpected error: %v", i, err)
		}
		if evt.Type != expected {
			t.Errorf("event %d: expected type %q, got %q", i, expected, evt.Type)
		}
	}

	// After message_stop, should get EOF
	_, err = reader.Next()
	if err != io.EOF {
		t.Errorf("expected EOF after message_stop, got %v", err)
	}
}

// TestHandle529Overloaded verifies 529 is handled the same as 429.
func TestHandle529Overloaded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(529)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"type":    "overloaded_error",
				"message": "Overloaded",
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	_, status, _, err := c.CreateMessage(context.Background(), &MessagesRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 100,
		Messages:  []Message{{Role: "user", Content: "test"}},
	})

	if status != 529 {
		t.Errorf("expected status 529, got %d", status)
	}
	if err == nil {
		t.Fatal("expected error for 529 response")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Type != "overloaded_error" {
		t.Errorf("expected error type overloaded_error, got %q", apiErr.Type)
	}
	if apiErr.Status != 529 {
		t.Errorf("expected error status 529, got %d", apiErr.Status)
	}
}

// TestHandle429RateLimit verifies 429 rate limit handling.
func TestHandle429RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"type":    "rate_limit_error",
				"message": "Rate limited",
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	_, _, _, err := c.CreateMessage(context.Background(), &MessagesRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 100,
		Messages:  []Message{{Role: "user", Content: "test"}},
	})

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Type != "rate_limit_error" {
		t.Errorf("expected rate_limit_error, got %q", apiErr.Type)
	}
}

// TestToolUseResponseDetection verifies tool_use blocks are present in response.
func TestToolUseResponseDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MessagesResponse{
			ID:   "msg-1",
			Type: "message",
			Role: "assistant",
			Content: []ContentBlock{
				{Type: "text", Text: "I'll look that up for you."},
				{
					Type:  "tool_use",
					ID:    "toolu_01A",
					Name:  "get_weather",
					Input: map[string]any{"location": "San Francisco"},
				},
			},
			Model:      "claude-sonnet-4-6",
			StopReason: "tool_use",
			Usage:      Usage{InputTokens: 50, OutputTokens: 30},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	resp, _, _, err := c.CreateMessage(context.Background(), &MessagesRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 1024,
		Messages:  []Message{{Role: "user", Content: "What's the weather?"}},
		Tools: []Tool{{
			Name:        "get_weather",
			Description: "Get weather",
			InputSchema: map[string]any{"type": "object"},
		}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StopReason != "tool_use" {
		t.Errorf("expected stop_reason=tool_use, got %q", resp.StopReason)
	}

	// Find tool_use blocks
	var toolUseBlocks []ContentBlock
	for _, block := range resp.Content {
		if block.Type == "tool_use" {
			toolUseBlocks = append(toolUseBlocks, block)
		}
	}
	if len(toolUseBlocks) != 1 {
		t.Fatalf("expected 1 tool_use block, got %d", len(toolUseBlocks))
	}
	if toolUseBlocks[0].Name != "get_weather" {
		t.Errorf("expected tool name get_weather, got %q", toolUseBlocks[0].Name)
	}
	if toolUseBlocks[0].ID != "toolu_01A" {
		t.Errorf("expected tool ID toolu_01A, got %q", toolUseBlocks[0].ID)
	}
}

// TestUsageExtraction verifies token usage is correctly parsed.
func TestUsageExtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MessagesResponse{
			ID:         "msg-1",
			Type:       "message",
			Role:       "assistant",
			Content:    []ContentBlock{{Type: "text", Text: "Hi"}},
			Model:      "claude-opus-4-6",
			StopReason: "end_turn",
			Usage: Usage{
				InputTokens:              150,
				OutputTokens:             42,
				CacheCreationInputTokens: 100,
				CacheReadInputTokens:     50,
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	resp, _, _, err := c.CreateMessage(context.Background(), &MessagesRequest{
		Model:     "claude-opus-4-6",
		MaxTokens: 100,
		Messages:  []Message{{Role: "user", Content: "test"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Usage.InputTokens != 150 {
		t.Errorf("expected input_tokens=150, got %d", resp.Usage.InputTokens)
	}
	if resp.Usage.OutputTokens != 42 {
		t.Errorf("expected output_tokens=42, got %d", resp.Usage.OutputTokens)
	}
	if resp.Usage.CacheCreationInputTokens != 100 {
		t.Errorf("expected cache_creation_input_tokens=100, got %d", resp.Usage.CacheCreationInputTokens)
	}
	if resp.Usage.CacheReadInputTokens != 50 {
		t.Errorf("expected cache_read_input_tokens=50, got %d", resp.Usage.CacheReadInputTokens)
	}
}

// TestCostCalculation verifies cost estimation for known models.
func TestCostCalculation(t *testing.T) {
	tests := []struct {
		model      string
		usage      Usage
		wantInput  float64
		wantOutput float64
	}{
		{
			model:      "claude-opus-4-6",
			usage:      Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000},
			wantInput:  15.0,
			wantOutput: 75.0,
		},
		{
			model:      "claude-sonnet-4-6",
			usage:      Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000},
			wantInput:  3.0,
			wantOutput: 15.0,
		},
		{
			model:      "claude-haiku-4-5",
			usage:      Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000},
			wantInput:  0.80,
			wantOutput: 4.0,
		},
		{
			model:      "claude-sonnet-4-6",
			usage:      Usage{InputTokens: 500, OutputTokens: 100},
			wantInput:  0.0015,
			wantOutput: 0.0015,
		},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			cost := EstimateCost(tt.model, tt.usage)
			if cost.Currency != "USD" {
				t.Errorf("expected currency USD, got %q", cost.Currency)
			}
			if diff := cost.InputCost - tt.wantInput; diff > 0.0001 || diff < -0.0001 {
				t.Errorf("input cost: expected %.4f, got %.4f", tt.wantInput, cost.InputCost)
			}
			if diff := cost.OutputCost - tt.wantOutput; diff > 0.0001 || diff < -0.0001 {
				t.Errorf("output cost: expected %.4f, got %.4f", tt.wantOutput, cost.OutputCost)
			}
			expectedTotal := tt.wantInput + tt.wantOutput
			if diff := cost.TotalCost - expectedTotal; diff > 0.0001 || diff < -0.0001 {
				t.Errorf("total cost: expected %.4f, got %.4f", expectedTotal, cost.TotalCost)
			}
		})
	}
}

// TestUnknownModelCost verifies zero cost for unknown models.
func TestUnknownModelCost(t *testing.T) {
	cost := EstimateCost("unknown-model", Usage{InputTokens: 1000, OutputTokens: 500})
	if cost.TotalCost != 0 {
		t.Errorf("expected zero cost for unknown model, got %f", cost.TotalCost)
	}
	if cost.Currency != "USD" {
		t.Errorf("expected USD currency, got %q", cost.Currency)
	}
}

// TestAuthError verifies 401 authentication error handling.
func TestAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"type":    "authentication_error",
				"message": "invalid x-api-key",
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "bad-key", "2023-06-01")
	_, status, _, err := c.CreateMessage(context.Background(), &MessagesRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 100,
		Messages:  []Message{{Role: "user", Content: "test"}},
	})

	if status != 401 {
		t.Errorf("expected status 401, got %d", status)
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Type != "authentication_error" {
		t.Errorf("expected authentication_error, got %q", apiErr.Type)
	}
}

// TestStreamError verifies streaming 529 error handling.
func TestStreamError529(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(529)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"type":    "overloaded_error",
				"message": "Overloaded",
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	_, status, _, err := c.CreateMessageStream(context.Background(), &MessagesRequest{
		Model:     "claude-sonnet-4-6",
		MaxTokens: 100,
		Messages:  []Message{{Role: "user", Content: "test"}},
	})

	if status != 529 {
		t.Errorf("expected status 529, got %d", status)
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Type != "overloaded_error" {
		t.Errorf("expected overloaded_error, got %q", apiErr.Type)
	}
}

// TestConnectionPooling verifies the client reuses connections.
func TestConnectionPooling(t *testing.T) {
	c := NewClient("https://api.anthropic.com", "key", "2023-06-01")
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.MaxIdleConns != 100 {
		t.Errorf("expected MaxIdleConns=100, got %d", transport.MaxIdleConns)
	}
	if transport.MaxIdleConnsPerHost != 20 {
		t.Errorf("expected MaxIdleConnsPerHost=20, got %d", transport.MaxIdleConnsPerHost)
	}
}

// TestBatchOperations tests batch API client methods.
func TestBatchOperations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/messages/batches":
			json.NewEncoder(w).Encode(BatchResponse{
				ID:               "batch_01",
				Type:             "message_batch",
				ProcessingStatus: "in_progress",
				CreatedAt:        "2026-03-20T00:00:00Z",
			})
		case r.Method == "GET" && r.URL.Path == "/v1/messages/batches":
			json.NewEncoder(w).Encode(BatchListResponse{
				Data:    []BatchResponse{{ID: "batch_01", ProcessingStatus: "ended"}},
				HasMore: false,
			})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/messages/batches/batch_01"):
			json.NewEncoder(w).Encode(BatchResponse{
				ID:               "batch_01",
				ProcessingStatus: "ended",
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/cancel"):
			json.NewEncoder(w).Encode(BatchResponse{
				ID:               "batch_01",
				ProcessingStatus: "canceling",
			})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	ctx := context.Background()

	// Create
	batchResp, _, _, err := c.CreateBatch(ctx, &BatchRequest{
		Requests: []BatchItem{{
			CustomID: "req-1",
			Params: MessagesRequest{
				Model:     "claude-sonnet-4-6",
				MaxTokens: 100,
				Messages:  []Message{{Role: "user", Content: "test"}},
			},
		}},
	})
	if err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	if batchResp.ID != "batch_01" {
		t.Errorf("expected batch ID batch_01, got %q", batchResp.ID)
	}

	// List
	listResp, _, _, err := c.ListBatches(ctx, 10, "")
	if err != nil {
		t.Fatalf("ListBatches: %v", err)
	}
	if len(listResp.Data) != 1 {
		t.Errorf("expected 1 batch, got %d", len(listResp.Data))
	}

	// Get
	getResp, _, _, err := c.GetBatch(ctx, "batch_01")
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if getResp.ProcessingStatus != "ended" {
		t.Errorf("expected status ended, got %q", getResp.ProcessingStatus)
	}

	// Cancel
	cancelResp, _, _, err := c.CancelBatch(ctx, "batch_01")
	if err != nil {
		t.Fatalf("CancelBatch: %v", err)
	}
	if cancelResp.ProcessingStatus != "canceling" {
		t.Errorf("expected status canceling, got %q", cancelResp.ProcessingStatus)
	}
}

// TestListModels tests the models list endpoint.
func TestListModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("expected path /v1/models, got %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ModelsResponse{
			Data: []ModelInfo{
				{ID: "claude-sonnet-4-6", DisplayName: "Claude Sonnet 4.6", Type: "model"},
				{ID: "claude-opus-4-6", DisplayName: "Claude Opus 4.6", Type: "model"},
			},
			HasMore: false,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "key", "2023-06-01")
	resp, _, _, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if len(resp.Data) != 2 {
		t.Errorf("expected 2 models, got %d", len(resp.Data))
	}
}
