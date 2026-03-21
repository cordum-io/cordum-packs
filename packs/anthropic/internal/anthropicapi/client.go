package anthropicapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- Request / Response types ---

// MessagesRequest represents a request to the Anthropic Messages API.
type MessagesRequest struct {
	Model         string         `json:"model"`
	MaxTokens     int            `json:"max_tokens"`
	Messages      []Message      `json:"messages"`
	System        any            `json:"system,omitempty"`
	Temperature   *float64       `json:"temperature,omitempty"`
	TopP          *float64       `json:"top_p,omitempty"`
	TopK          *int           `json:"top_k,omitempty"`
	StopSequences []string       `json:"stop_sequences,omitempty"`
	Tools         []Tool         `json:"tools,omitempty"`
	ToolChoice    any            `json:"tool_choice,omitempty"`
	Thinking      *ThinkingBlock `json:"thinking,omitempty"`
	Metadata      *Metadata      `json:"metadata,omitempty"`
	Stream        bool           `json:"stream,omitempty"`
}

// Message represents a conversation message.
type Message struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string or []ContentBlock
}

// ContentBlock represents a content block in a message.
type ContentBlock struct {
	Type   string       `json:"type"`
	Text   string       `json:"text,omitempty"`
	Source *ImageSource `json:"source,omitempty"`
	// tool_use fields
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Input any    `json:"input,omitempty"`
	// tool_result fields
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content_  any    `json:"content,omitempty"` //nolint:revive // matches API field name
	IsError   bool   `json:"is_error,omitempty"`
	// thinking fields
	Thinking string `json:"thinking,omitempty"`
}

// ImageSource represents image data for vision inputs.
type ImageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type"`
	Data      string `json:"data,omitempty"`
	URL       string `json:"url,omitempty"`
}

// Tool defines a tool for tool use.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"input_schema"`
}

// ThinkingBlock configures extended thinking.
type ThinkingBlock struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens"`
}

// Metadata holds request metadata.
type Metadata struct {
	UserID string `json:"user_id,omitempty"`
}

// MessagesResponse represents a response from the Messages API.
type MessagesResponse struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Role         string         `json:"role"`
	Content      []ContentBlock `json:"content"`
	Model        string         `json:"model"`
	StopReason   string         `json:"stop_reason"`
	StopSequence string         `json:"stop_sequence,omitempty"`
	Usage        Usage          `json:"usage"`
}

// Usage tracks token consumption.
type Usage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
}

// BatchRequest represents a batch creation request.
type BatchRequest struct {
	Requests []BatchItem `json:"requests"`
}

// BatchItem is a single item in a batch.
type BatchItem struct {
	CustomID string          `json:"custom_id"`
	Params   MessagesRequest `json:"params"`
}

// BatchResponse represents a batch API response.
type BatchResponse struct {
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	ProcessingStatus  string    `json:"processing_status"`
	RequestCounts     any       `json:"request_counts"`
	EndedAt           string    `json:"ended_at,omitempty"`
	CreatedAt         string    `json:"created_at"`
	ExpiresAt         string    `json:"expires_at,omitempty"`
	CancelInitiatedAt string    `json:"cancel_initiated_at,omitempty"`
	ResultsURL        string    `json:"results_url,omitempty"`
}

// BatchListResponse represents a paginated batch list.
type BatchListResponse struct {
	Data    []BatchResponse `json:"data"`
	HasMore bool            `json:"has_more"`
	FirstID string          `json:"first_id,omitempty"`
	LastID  string          `json:"last_id,omitempty"`
}

// ModelsResponse represents a list models response.
type ModelsResponse struct {
	Data    []ModelInfo `json:"data"`
	HasMore bool        `json:"has_more"`
	FirstID string      `json:"first_id,omitempty"`
	LastID  string      `json:"last_id,omitempty"`
}

// ModelInfo describes a single model.
type ModelInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
	Type        string `json:"type"`
}

// APIError represents an error response from the Anthropic API.
type APIError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("anthropic API error (status %d, type %s): %s", e.Status, e.Type, e.Message)
}

// --- SSE Stream types ---

// StreamEvent represents a parsed SSE event from the streaming API.
type StreamEvent struct {
	Type  string // event type: message_start, content_block_start, content_block_delta, content_block_stop, message_delta, message_stop
	Data  json.RawMessage
	Index int // content block index (for delta events)
}

// StreamDelta contains a text or tool_use delta.
type StreamDelta struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	// For input_json_delta
	PartialJSON string `json:"partial_json,omitempty"`
}

// StreamReader reads SSE events from a streaming response.
type StreamReader struct {
	body    io.ReadCloser
	scanner *bufio.Scanner
	done    bool
	mu      sync.Mutex
}

// Next returns the next SSE event, or io.EOF when done.
func (r *StreamReader) Next() (*StreamEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.done {
		return nil, io.EOF
	}

	var eventType string
	var dataLines []string

	for r.scanner.Scan() {
		line := r.scanner.Text()

		if line == "" {
			// Empty line = event boundary
			if eventType != "" || len(dataLines) > 0 {
				evt := &StreamEvent{
					Type: eventType,
					Data: json.RawMessage(strings.Join(dataLines, "\n")),
				}
				if eventType == "message_stop" {
					r.done = true
				}
				return evt, nil
			}
			continue
		}

		if v, ok := strings.CutPrefix(line, "event: "); ok {
			eventType = v
		} else if v, ok := strings.CutPrefix(line, "data: "); ok {
			dataLines = append(dataLines, v)
		}
	}

	if err := r.scanner.Err(); err != nil {
		return nil, fmt.Errorf("stream read error: %w", err)
	}

	r.done = true
	if eventType != "" || len(dataLines) > 0 {
		return &StreamEvent{
			Type: eventType,
			Data: json.RawMessage(strings.Join(dataLines, "\n")),
		}, nil
	}
	return nil, io.EOF
}

// Close closes the underlying response body.
func (r *StreamReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = true
	return r.body.Close()
}

// --- Cost calculation ---

// ModelPricing holds per-million-token pricing in USD.
type ModelPricing struct {
	InputPerMillion  float64
	OutputPerMillion float64
}

var modelPricing = map[string]ModelPricing{
	"claude-opus-4-6":   {InputPerMillion: 15.0, OutputPerMillion: 75.0},
	"claude-sonnet-4-6": {InputPerMillion: 3.0, OutputPerMillion: 15.0},
	"claude-haiku-4-5":  {InputPerMillion: 0.80, OutputPerMillion: 4.0},
}

// CostEstimate holds a computed cost estimate.
type CostEstimate struct {
	InputCost  float64 `json:"input_cost"`
	OutputCost float64 `json:"output_cost"`
	TotalCost  float64 `json:"total_cost"`
	Currency   string  `json:"currency"`
}

// EstimateCost computes the cost for a given model and usage.
func EstimateCost(model string, usage Usage) CostEstimate {
	pricing, ok := modelPricing[model]
	if !ok {
		return CostEstimate{Currency: "USD"}
	}
	inputCost := float64(usage.InputTokens) / 1_000_000 * pricing.InputPerMillion
	outputCost := float64(usage.OutputTokens) / 1_000_000 * pricing.OutputPerMillion
	return CostEstimate{
		InputCost:  inputCost,
		OutputCost: outputCost,
		TotalCost:  inputCost + outputCost,
		Currency:   "USD",
	}
}

// --- Client ---

// Client is an HTTP client for the Anthropic Messages API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	apiVersion string
	userAgent  string
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client (for connection pooling).
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) { cl.httpClient = c }
}

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) ClientOption {
	return func(cl *Client) { cl.userAgent = ua }
}

// NewClient creates a new Anthropic API client.
// Uses x-api-key header authentication (NOT Bearer token).
func NewClient(baseURL, apiKey, apiVersion string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		apiVersion: apiVersion,
		userAgent:  "cordum-anthropic-worker/0.1.0",
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", c.apiVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, result any) (int, string, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, "", fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, "", fmt.Errorf("create request: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	requestID := resp.Header.Get("request-id")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, requestID, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == 429 || resp.StatusCode == 529 {
		var apiErr struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error.Message != "" {
			return resp.StatusCode, requestID, &APIError{
				Type:    apiErr.Error.Type,
				Message: apiErr.Error.Message,
				Status:  resp.StatusCode,
			}
		}
		return resp.StatusCode, requestID, &APIError{
			Type:    "rate_limit_error",
			Message: fmt.Sprintf("rate limited (status %d)", resp.StatusCode),
			Status:  resp.StatusCode,
		}
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error.Message != "" {
			return resp.StatusCode, requestID, &APIError{
				Type:    apiErr.Error.Type,
				Message: apiErr.Error.Message,
				Status:  resp.StatusCode,
			}
		}
		return resp.StatusCode, requestID, &APIError{
			Type:    "api_error",
			Message: string(respBody),
			Status:  resp.StatusCode,
		}
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return resp.StatusCode, requestID, fmt.Errorf("decode response: %w", err)
		}
	}

	return resp.StatusCode, requestID, nil
}

// CreateMessage sends a non-streaming messages request.
func (c *Client) CreateMessage(ctx context.Context, req *MessagesRequest) (*MessagesResponse, int, string, error) {
	req.Stream = false
	var resp MessagesResponse
	status, requestID, err := c.doJSON(ctx, http.MethodPost, "/v1/messages", req, &resp)
	if err != nil {
		return nil, status, requestID, err
	}
	slog.Debug("anthropic messages response",
		"model", resp.Model,
		"stop_reason", resp.StopReason,
		"input_tokens", resp.Usage.InputTokens,
		"output_tokens", resp.Usage.OutputTokens,
	)
	return &resp, status, requestID, nil
}

// CreateMessageStream sends a streaming messages request and returns a StreamReader.
func (c *Client) CreateMessageStream(ctx context.Context, req *MessagesRequest) (*StreamReader, int, string, error) {
	req.Stream = true
	data, err := json.Marshal(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, 0, "", fmt.Errorf("create request: %w", err)
	}
	c.setHeaders(httpReq)
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, 0, "", fmt.Errorf("execute request: %w", err)
	}

	requestID := resp.Header.Get("request-id")

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		// Handle 529 same as 429
		if resp.StatusCode == 429 || resp.StatusCode == 529 {
			var apiErr struct {
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &apiErr) == nil && apiErr.Error.Message != "" {
				return nil, resp.StatusCode, requestID, &APIError{
					Type:    apiErr.Error.Type,
					Message: apiErr.Error.Message,
					Status:  resp.StatusCode,
				}
			}
		}

		var apiErr struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Error.Message != "" {
			return nil, resp.StatusCode, requestID, &APIError{
				Type:    apiErr.Error.Type,
				Message: apiErr.Error.Message,
				Status:  resp.StatusCode,
			}
		}
		return nil, resp.StatusCode, requestID, &APIError{
			Type:    "api_error",
			Message: string(body),
			Status:  resp.StatusCode,
		}
	}

	reader := &StreamReader{
		body:    resp.Body,
		scanner: bufio.NewScanner(resp.Body),
	}
	return reader, resp.StatusCode, requestID, nil
}

// CreateBatch creates a new message batch.
func (c *Client) CreateBatch(ctx context.Context, req *BatchRequest) (*BatchResponse, int, string, error) {
	var resp BatchResponse
	status, requestID, err := c.doJSON(ctx, http.MethodPost, "/v1/messages/batches", req, &resp)
	if err != nil {
		return nil, status, requestID, err
	}
	return &resp, status, requestID, nil
}

// ListBatches lists message batches.
func (c *Client) ListBatches(ctx context.Context, limit int, afterID string) (*BatchListResponse, int, string, error) {
	path := "/v1/messages/batches"
	params := make([]string, 0, 2)
	if limit > 0 {
		params = append(params, fmt.Sprintf("limit=%d", limit))
	}
	if afterID != "" {
		params = append(params, fmt.Sprintf("after_id=%s", afterID))
	}
	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	var resp BatchListResponse
	status, requestID, err := c.doJSON(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, status, requestID, err
	}
	return &resp, status, requestID, nil
}

// GetBatch retrieves a specific batch by ID.
func (c *Client) GetBatch(ctx context.Context, batchID string) (*BatchResponse, int, string, error) {
	var resp BatchResponse
	status, requestID, err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/v1/messages/batches/%s", batchID), nil, &resp)
	if err != nil {
		return nil, status, requestID, err
	}
	return &resp, status, requestID, nil
}

// CancelBatch cancels a batch by ID.
func (c *Client) CancelBatch(ctx context.Context, batchID string) (*BatchResponse, int, string, error) {
	var resp BatchResponse
	status, requestID, err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("/v1/messages/batches/%s/cancel", batchID), nil, &resp)
	if err != nil {
		return nil, status, requestID, err
	}
	return &resp, status, requestID, nil
}

// ListModels lists available models.
func (c *Client) ListModels(ctx context.Context) (*ModelsResponse, int, string, error) {
	var resp ModelsResponse
	status, requestID, err := c.doJSON(ctx, http.MethodGet, "/v1/models", nil, &resp)
	if err != nil {
		return nil, status, requestID, err
	}
	return &resp, status, requestID, nil
}
