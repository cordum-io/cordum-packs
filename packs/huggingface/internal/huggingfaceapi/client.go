package huggingfaceapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client wraps HTTP calls to both HF Inference API and Hub API.
type Client struct {
	httpClient   *http.Client
	inferenceURL string // https://api-inference.huggingface.co
	hubURL       string // https://huggingface.co/api
	token        string
}

// NewClient creates a new HuggingFace client with dual base URLs.
func NewClient(inferenceURL, hubURL, token string) *Client {
	return &Client{
		inferenceURL: strings.TrimRight(inferenceURL, "/"),
		hubURL:       strings.TrimRight(hubURL, "/"),
		token:        token,
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

// Inference calls the serverless inference API for a model.
func (c *Client) Inference(ctx context.Context, modelID string, body any, waitForModel bool) (any, int, error) {
	if modelID == "" {
		return nil, 0, fmt.Errorf("model is required")
	}

	reqURL := fmt.Sprintf("%s/models/%s", c.inferenceURL, modelID)
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")
	if waitForModel {
		req.Header.Set("X-Wait-For-Model", "true")
	}

	return c.doRequest(req)
}

// Embed calls feature extraction for embeddings.
func (c *Client) Embed(ctx context.Context, modelID string, inputs any, waitForModel bool) (any, int, error) {
	if modelID == "" {
		return nil, 0, fmt.Errorf("model is required")
	}

	reqURL := fmt.Sprintf("%s/pipeline/feature-extraction/%s", c.inferenceURL, modelID)
	body := map[string]any{"inputs": inputs}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")
	if waitForModel {
		req.Header.Set("X-Wait-For-Model", "true")
	}

	return c.doRequest(req)
}

// SearchModels searches the model hub.
func (c *Client) SearchModels(ctx context.Context, params map[string]any) (any, int, error) {
	reqURL := c.hubURL + "/models"
	query := url.Values{}
	if search, ok := params["search"].(string); ok && search != "" {
		query.Set("search", search)
	}
	if author, ok := params["author"].(string); ok && author != "" {
		query.Set("author", author)
	}
	if filter, ok := params["filter"].(string); ok && filter != "" {
		query.Set("filter", filter)
	}
	if sort, ok := params["sort"].(string); ok && sort != "" {
		query.Set("sort", sort)
	}
	if dir, ok := params["direction"].(string); ok && dir != "" {
		query.Set("direction", dir)
	}
	if limit, ok := params["limit"].(float64); ok && limit > 0 {
		query.Set("limit", fmt.Sprintf("%d", int(limit)))
	}
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	c.setAuth(req)

	return c.doRequest(req)
}

// GetModel gets model metadata from the hub.
func (c *Client) GetModel(ctx context.Context, modelID string) (any, int, error) {
	if modelID == "" {
		return nil, 0, fmt.Errorf("model_id is required")
	}
	reqURL := fmt.Sprintf("%s/models/%s", c.hubURL, modelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	c.setAuth(req)
	return c.doRequest(req)
}

// GetSpace gets space metadata.
func (c *Client) GetSpace(ctx context.Context, spaceID string) (any, int, error) {
	if spaceID == "" {
		return nil, 0, fmt.Errorf("space_id is required")
	}
	reqURL := fmt.Sprintf("%s/spaces/%s", c.hubURL, spaceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	c.setAuth(req)
	return c.doRequest(req)
}

// RestartSpace restarts a space.
func (c *Client) RestartSpace(ctx context.Context, spaceID string) (any, int, error) {
	if spaceID == "" {
		return nil, 0, fmt.Errorf("space_id is required")
	}
	reqURL := fmt.Sprintf("%s/spaces/%s/restart", c.hubURL, spaceID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	c.setAuth(req)
	return c.doRequest(req)
}

func (c *Client) setAuth(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

func (c *Client) doRequest(req *http.Request) (any, int, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	// Handle 503 Model Loading
	if resp.StatusCode == 503 {
		var loadingResp struct {
			Error         string  `json:"error"`
			EstimatedTime float64 `json:"estimated_time"`
		}
		if json.Unmarshal(body, &loadingResp) == nil && loadingResp.EstimatedTime > 0 {
			return map[string]any{
				"loading":        true,
				"error":          loadingResp.Error,
				"estimated_time": loadingResp.EstimatedTime,
			}, 503, fmt.Errorf("model is loading (estimated %.0fs) — set wait_for_model=true to wait", loadingResp.EstimatedTime)
		}
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Error != "" {
			return nil, resp.StatusCode, fmt.Errorf("HF API error (status %d): %s", resp.StatusCode, apiErr.Error)
		}
		return nil, resp.StatusCode, fmt.Errorf("HF API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result any
	if json.Unmarshal(body, &result) != nil {
		return string(body), resp.StatusCode, nil
	}
	return result, resp.StatusCode, nil
}
