package n8napi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const apiKeyHeader = "X-N8N-API-KEY"

// APIError captures non-2xx n8n responses.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("n8n api error (status %d): %s", e.StatusCode, e.Body)
}

// Client is a pooled n8n REST API client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new n8n REST client.
func NewClient(baseURL, apiKey string, timeout time.Duration) (*Client, error) {
	normalized, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("n8n api key required")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL: normalized,
		apiKey:  strings.TrimSpace(apiKey),
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}, nil
}

// ListWorkflows lists workflows with optional filters.
func (c *Client) ListWorkflows(ctx context.Context, params map[string]any) (map[string]any, error) {
	query := url.Values{}
	if active, ok := params["active"].(bool); ok {
		query.Set("active", strconv.FormatBool(active))
	}
	if tags := strings.TrimSpace(stringValue(params["tags"])); tags != "" {
		query.Set("tags", tags)
	}
	if limit := intValue(params["limit"]); limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if cursor := strings.TrimSpace(stringValue(params["cursor"])); cursor != "" {
		query.Set("cursor", cursor)
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/workflows", query, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetWorkflow gets a workflow by id.
func (c *Client) GetWorkflow(ctx context.Context, workflowID string) (map[string]any, error) {
	workflowID = strings.TrimSpace(workflowID)
	if workflowID == "" {
		return nil, fmt.Errorf("workflow_id required")
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/workflows/"+url.PathEscape(workflowID), nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExecuteWorkflow triggers an n8n workflow by id.
func (c *Client) ExecuteWorkflow(ctx context.Context, workflowID string, payload map[string]any) (map[string]any, error) {
	workflowID = strings.TrimSpace(workflowID)
	if workflowID == "" {
		return nil, fmt.Errorf("workflow_id required")
	}
	if payload == nil {
		payload = map[string]any{}
	}

	paths := []string{
		"/workflows/" + url.PathEscape(workflowID) + "/execute",
		"/workflows/" + url.PathEscape(workflowID) + "/run",
	}
	var lastErr error
	for _, apiPath := range paths {
		var out map[string]any
		err := c.doJSON(ctx, http.MethodPost, apiPath, nil, payload, &out)
		if err == nil {
			return out, nil
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed) {
			lastErr = err
			continue
		}
		return nil, err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("workflow execution failed")
}

// GetExecution gets an execution by id.
func (c *Client) GetExecution(ctx context.Context, executionID string, includeData bool) (map[string]any, error) {
	executionID = strings.TrimSpace(executionID)
	if executionID == "" {
		return nil, fmt.Errorf("execution_id required")
	}
	query := url.Values{}
	if includeData {
		query.Set("includeData", "true")
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/executions/"+url.PathEscape(executionID), query, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListExecutions lists executions with optional filters.
func (c *Client) ListExecutions(ctx context.Context, params map[string]any) (map[string]any, error) {
	query := url.Values{}
	for _, key := range []string{"workflowId", "status", "cursor"} {
		if value := strings.TrimSpace(stringValue(params[key])); value != "" {
			query.Set(key, value)
		}
	}
	if limit := intValue(params["limit"]); limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if includeData, ok := params["includeData"].(bool); ok {
		query.Set("includeData", strconv.FormatBool(includeData))
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/executions", query, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ActivateWorkflow activates a workflow.
func (c *Client) ActivateWorkflow(ctx context.Context, workflowID string) (map[string]any, error) {
	return c.workflowMutation(ctx, workflowID, "/activate")
}

// DeactivateWorkflow deactivates a workflow.
func (c *Client) DeactivateWorkflow(ctx context.Context, workflowID string) (map[string]any, error) {
	return c.workflowMutation(ctx, workflowID, "/deactivate")
}

// ListCredentials lists available credentials.
func (c *Client) ListCredentials(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/credentials", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) workflowMutation(ctx context.Context, workflowID, suffix string) (map[string]any, error) {
	workflowID = strings.TrimSpace(workflowID)
	if workflowID == "" {
		return nil, fmt.Errorf("workflow_id required")
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodPost, "/workflows/"+url.PathEscape(workflowID)+suffix, nil, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	requestURL := c.baseURL + path
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(apiKeyHeader, c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		bodyText := strings.TrimSpace(string(data))
		if bodyText == "" {
			bodyText = resp.Status
		}
		return &APIError{StatusCode: resp.StatusCode, Body: bodyText}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func normalizeBaseURL(value string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(value), "/")
	if trimmed == "" {
		return "", fmt.Errorf("n8n base url required")
	}
	if strings.HasSuffix(trimmed, "/api/v1") {
		return trimmed, nil
	}
	return trimmed + "/api/v1", nil
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprint(typed)
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}
