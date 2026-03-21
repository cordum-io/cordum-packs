package mistralapi

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
	"time"
)

// --- Request types ---

// ChatRequest represents a Mistral chat completion request.
type ChatRequest struct {
	Model          string    `json:"model"`
	Messages       []Message `json:"messages"`
	Temperature    *float64  `json:"temperature,omitempty"`
	MaxTokens      *int      `json:"max_tokens,omitempty"`
	TopP           *float64  `json:"top_p,omitempty"`
	Tools          []Tool    `json:"tools,omitempty"`
	ToolChoice     any       `json:"tool_choice,omitempty"`
	ResponseFormat any       `json:"response_format,omitempty"`
	SafePrompt     bool      `json:"safe_prompt,omitempty"`
	Stream         bool      `json:"stream,omitempty"`
	RandomSeed     *int      `json:"random_seed,omitempty"`
}

// Message is a chat message.
type Message struct {
	Role       string `json:"role"`
	Content    string `json:"content"`
	ToolCalls  any    `json:"tool_calls,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// Tool is a function calling tool.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction describes a callable function.
type ToolFunction struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
}

// EmbeddingRequest represents an embedding request.
type EmbeddingRequest struct {
	Model          string `json:"model"`
	Input          any    `json:"input"` // string or []string
	EncodingFormat string `json:"encoding_format,omitempty"`
}

// FIMRequest represents a fill-in-the-middle request.
type FIMRequest struct {
	Model       string   `json:"model"`
	Prompt      string   `json:"prompt"`
	Suffix      string   `json:"suffix,omitempty"`
	MaxTokens   *int     `json:"max_tokens,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	Stop        []string `json:"stop,omitempty"`
}

// --- Response types ---

// ChatResponse is the chat completion response.
type ChatResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Model   string         `json:"model"`
	Choices []ChatChoice   `json:"choices"`
	Usage   Usage          `json:"usage"`
}

// ChatChoice is a single choice in the response.
type ChatChoice struct {
	Index        int            `json:"index"`
	Message      ChoiceMessage  `json:"message"`
	FinishReason string         `json:"finish_reason"`
}

// ChoiceMessage is the message in a choice.
type ChoiceMessage struct {
	Role      string `json:"role"`
	Content   string `json:"content"`
	ToolCalls any    `json:"tool_calls,omitempty"`
}

// Usage tracks token consumption.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// EmbeddingResponse is the embedding response.
type EmbeddingResponse struct {
	ID     string           `json:"id"`
	Object string           `json:"object"`
	Model  string           `json:"model"`
	Data   []EmbeddingData  `json:"data"`
	Usage  Usage            `json:"usage"`
}

// EmbeddingData is a single embedding.
type EmbeddingData struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

// FIMResponse is the fill-in-the-middle response.
type FIMResponse struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Model   string      `json:"model"`
	Choices []FIMChoice `json:"choices"`
	Usage   Usage       `json:"usage"`
}

// FIMChoice is a FIM completion choice.
type FIMChoice struct {
	Index        int    `json:"index"`
	Message      any    `json:"message,omitempty"`
	Text         string `json:"text,omitempty"`
	FinishReason string `json:"finish_reason"`
}

// APIError represents a Mistral API error.
type APIError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mistral API error (status %d): %s", e.Status, e.Message)
}

// --- Cost calculation ---

type ModelPricing struct {
	InputPerMillion  float64
	OutputPerMillion float64
}

var modelPricing = map[string]ModelPricing{
	"mistral-large-latest":  {InputPerMillion: 2.0, OutputPerMillion: 6.0},
	"mistral-medium-latest": {InputPerMillion: 2.7, OutputPerMillion: 8.1},
	"mistral-small-latest":  {InputPerMillion: 0.2, OutputPerMillion: 0.6},
	"codestral-latest":      {InputPerMillion: 0.3, OutputPerMillion: 0.9},
	"open-mistral-nemo":     {InputPerMillion: 0.15, OutputPerMillion: 0.15},
	"mistral-embed":         {InputPerMillion: 0.1, OutputPerMillion: 0.0},
}

// CostEstimate holds computed cost.
type CostEstimate struct {
	InputCost  float64 `json:"input_cost"`
	OutputCost float64 `json:"output_cost"`
	TotalCost  float64 `json:"total_cost"`
	Currency   string  `json:"currency"`
}

// EstimateCost computes cost for a given model and usage.
func EstimateCost(model string, usage Usage) CostEstimate {
	pricing, ok := modelPricing[model]
	if !ok {
		return CostEstimate{Currency: "USD"}
	}
	inputCost := float64(usage.PromptTokens) / 1_000_000 * pricing.InputPerMillion
	outputCost := float64(usage.CompletionTokens) / 1_000_000 * pricing.OutputPerMillion
	return CostEstimate{
		InputCost:  inputCost,
		OutputCost: outputCost,
		TotalCost:  inputCost + outputCost,
		Currency:   "USD",
	}
}

// --- Client ---

// Client is an HTTP client for the Mistral API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// NewClient creates a new Mistral API client with Bearer auth.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, result any) (int, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		var apiErr struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Message != "" {
			return resp.StatusCode, &APIError{Type: apiErr.Type, Message: apiErr.Message, Status: resp.StatusCode}
		}
		return resp.StatusCode, &APIError{Type: "api_error", Message: string(respBody), Status: resp.StatusCode}
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Message != "" {
			return resp.StatusCode, &APIError{Type: apiErr.Type, Message: apiErr.Message, Status: resp.StatusCode}
		}
		return resp.StatusCode, &APIError{Type: "api_error", Message: string(respBody), Status: resp.StatusCode}
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// ChatCompletion sends a non-streaming chat completion request.
func (c *Client) ChatCompletion(ctx context.Context, req *ChatRequest) (*ChatResponse, int, error) {
	req.Stream = false
	var resp ChatResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/chat/completions", req, &resp)
	if err != nil {
		return nil, status, err
	}
	slog.Debug("mistral chat response",
		"model", resp.Model,
		"prompt_tokens", resp.Usage.PromptTokens,
		"completion_tokens", resp.Usage.CompletionTokens,
	)
	return &resp, status, nil
}

// ChatCompletionStream sends a streaming chat completion request.
func (c *Client) ChatCompletionStream(ctx context.Context, req *ChatRequest) (*bufio.Scanner, io.Closer, int, error) {
	req.Stream = true
	data, err := json.Marshal(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, nil, 0, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, 0, err
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, resp.StatusCode, &APIError{Type: "api_error", Message: string(body), Status: resp.StatusCode}
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB max line, matching OpenAI pack
	return scanner, resp.Body, resp.StatusCode, nil
}

// CreateEmbedding creates embeddings.
func (c *Client) CreateEmbedding(ctx context.Context, req *EmbeddingRequest) (*EmbeddingResponse, int, error) {
	var resp EmbeddingResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/embeddings", req, &resp)
	if err != nil {
		return nil, status, err
	}
	return &resp, status, nil
}

// FIMCompletion sends a fill-in-the-middle request.
func (c *Client) FIMCompletion(ctx context.Context, req *FIMRequest) (*FIMResponse, int, error) {
	var resp FIMResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/fim/completions", req, &resp)
	if err != nil {
		return nil, status, err
	}
	return &resp, status, nil
}

// ListModels lists available models.
func (c *Client) ListModels(ctx context.Context) (any, int, error) {
	var resp any
	status, err := c.doJSON(ctx, http.MethodGet, "/v1/models", nil, &resp)
	if err != nil {
		return nil, status, err
	}
	return resp, status, nil
}
