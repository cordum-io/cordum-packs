package cohereapi

import (
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

// ChatRequest is a Cohere v2 chat request.
type ChatRequest struct {
	Model       string    `json:"model,omitempty"`
	Message     string    `json:"message"`
	Preamble    string    `json:"preamble,omitempty"`
	ChatHistory []ChatMsg `json:"chat_history,omitempty"`
	Documents   any       `json:"documents,omitempty"`
	Connectors  any       `json:"connectors,omitempty"`
	Temperature *float64  `json:"temperature,omitempty"`
	MaxTokens   *int      `json:"max_tokens,omitempty"`
	Tools       any       `json:"tools,omitempty"`
	ToolResults any       `json:"tool_results,omitempty"`
}

// ChatMsg is a chat history message.
type ChatMsg struct {
	Role    string `json:"role"`
	Message string `json:"message"`
}

// EmbedRequest is a Cohere embed request.
type EmbedRequest struct {
	Model          string   `json:"model,omitempty"`
	Texts          []string `json:"texts"`
	InputType      string   `json:"input_type"`
	EmbeddingTypes []string `json:"embedding_types,omitempty"`
	Truncate       string   `json:"truncate,omitempty"`
}

// RerankRequest is a Cohere rerank request.
type RerankRequest struct {
	Model           string `json:"model,omitempty"`
	Query           string `json:"query"`
	Documents       any    `json:"documents"`
	TopN            *int   `json:"top_n,omitempty"`
	ReturnDocuments bool   `json:"return_documents,omitempty"`
}

// ClassifyRequest is a Cohere classify request.
type ClassifyRequest struct {
	Model    string            `json:"model,omitempty"`
	Inputs   []string          `json:"inputs"`
	Examples []ClassifyExample `json:"examples,omitempty"`
	Preset   string            `json:"preset,omitempty"`
	Truncate string            `json:"truncate,omitempty"`
}

// ClassifyExample is a labeled example.
type ClassifyExample struct {
	Text  string `json:"text"`
	Label string `json:"label"`
}

// --- Response types ---

// ChatResponse is the chat response.
type ChatResponse struct {
	Text         string `json:"text"`
	GenerationID string `json:"generation_id"`
	FinishReason string `json:"finish_reason"`
	Citations    any    `json:"citations,omitempty"`
	ToolCalls    any    `json:"tool_calls,omitempty"`
	Meta         *Meta  `json:"meta,omitempty"`
}

// EmbedResponse is the embed response.
type EmbedResponse struct {
	ID         string      `json:"id"`
	Embeddings any         `json:"embeddings"`
	Texts      []string    `json:"texts"`
	Meta       *Meta       `json:"meta,omitempty"`
}

// RerankResponse is the rerank response.
type RerankResponse struct {
	ID      string        `json:"id"`
	Results []RerankResult `json:"results"`
	Meta    *Meta         `json:"meta,omitempty"`
}

// RerankResult is a single rerank result.
type RerankResult struct {
	Index          int     `json:"index"`
	RelevanceScore float64 `json:"relevance_score"`
	Document       any     `json:"document,omitempty"`
}

// ClassifyResponse is the classify response.
type ClassifyResponse struct {
	ID              string              `json:"id"`
	Classifications []ClassifyResult    `json:"classifications"`
	Meta            *Meta               `json:"meta,omitempty"`
}

// ClassifyResult is a single classification result.
type ClassifyResult struct {
	ID         string            `json:"id"`
	Input      string            `json:"input"`
	Prediction string            `json:"prediction"`
	Confidence float64           `json:"confidence"`
	Labels     map[string]Label  `json:"labels,omitempty"`
}

// Label is a classification label with confidence.
type Label struct {
	Confidence float64 `json:"confidence"`
}

// Meta holds response metadata.
type Meta struct {
	APIVersion  *APIVersion  `json:"api_version,omitempty"`
	BilledUnits *BilledUnits `json:"billed_units,omitempty"`
	Tokens      *Tokens      `json:"tokens,omitempty"`
}

// APIVersion is the API version info.
type APIVersion struct {
	Version string `json:"version"`
}

// BilledUnits tracks Cohere billing.
type BilledUnits struct {
	InputTokens     float64 `json:"input_tokens,omitempty"`
	OutputTokens    float64 `json:"output_tokens,omitempty"`
	SearchUnits     float64 `json:"search_units,omitempty"`
	Classifications float64 `json:"classifications,omitempty"`
}

// Tokens tracks raw token counts.
type Tokens struct {
	InputTokens  int `json:"input_tokens,omitempty"`
	OutputTokens int `json:"output_tokens,omitempty"`
}

// APIError represents a Cohere API error.
type APIError struct {
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cohere API error (status %d): %s", e.Status, e.Message)
}

// --- Client ---

// Client is an HTTP client for the Cohere API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// NewClient creates a new Cohere API client with Bearer auth.
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
			return 0, fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Message != "" {
			return resp.StatusCode, &APIError{Message: apiErr.Message, Status: resp.StatusCode}
		}
		return resp.StatusCode, &APIError{Message: string(respBody), Status: resp.StatusCode}
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return resp.StatusCode, fmt.Errorf("decode: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// Chat sends a chat request.
func (c *Client) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, int, error) {
	var resp ChatResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/chat", req, &resp)
	if err != nil {
		return nil, status, err
	}
	slog.Debug("cohere chat", "finish_reason", resp.FinishReason)
	return &resp, status, nil
}

// Embed sends an embedding request.
func (c *Client) Embed(ctx context.Context, req *EmbedRequest) (*EmbedResponse, int, error) {
	var resp EmbedResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/embed", req, &resp)
	if err != nil {
		return nil, status, err
	}
	return &resp, status, nil
}

// Rerank sends a rerank request.
func (c *Client) Rerank(ctx context.Context, req *RerankRequest) (*RerankResponse, int, error) {
	var resp RerankResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/rerank", req, &resp)
	if err != nil {
		return nil, status, err
	}
	return &resp, status, nil
}

// Classify sends a classify request.
func (c *Client) Classify(ctx context.Context, req *ClassifyRequest) (*ClassifyResponse, int, error) {
	var resp ClassifyResponse
	status, err := c.doJSON(ctx, http.MethodPost, "/v1/classify", req, &resp)
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
