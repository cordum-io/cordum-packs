package gatewayclient

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

// Client starts Cordum workflow runs through the gateway API.
type Client struct {
	baseURL    string
	apiKey     string
	tenantID   string
	httpClient *http.Client
}

type startRunResponse struct {
	RunID string `json:"run_id"`
}

// New creates a gateway client with connection pooling.
func New(baseURL, apiKey, tenantID string) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   strings.TrimSpace(apiKey),
		tenantID: strings.TrimSpace(tenantID),
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// StartRun triggers a Cordum workflow run.
func (c *Client) StartRun(ctx context.Context, workflowID string, payload any, idempotencyKey string) (string, error) {
	workflowID = strings.TrimSpace(workflowID)
	if workflowID == "" {
		return "", fmt.Errorf("workflow id required")
	}
	path := "/api/v1/workflows/" + url.PathEscape(workflowID) + "/runs"
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		request.Header.Set("X-API-Key", c.apiKey)
	}
	if c.tenantID != "" {
		request.Header.Set("X-Tenant-ID", c.tenantID)
	}
	if strings.TrimSpace(idempotencyKey) != "" {
		request.Header.Set("Idempotency-Key", strings.TrimSpace(idempotencyKey))
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer response.Body.Close()

	data, _ := io.ReadAll(response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(data))
		if message == "" {
			message = response.Status
		}
		return "", fmt.Errorf("gateway error: %s", message)
	}
	var decoded startRunResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if decoded.RunID == "" {
		return "", fmt.Errorf("gateway response missing run_id")
	}
	return decoded.RunID, nil
}
