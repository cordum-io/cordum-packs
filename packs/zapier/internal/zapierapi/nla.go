package zapierapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	apiKeyHeader = "x-api-key"
	authHeader   = "Authorization"
)

// APIError captures non-2xx Zapier responses.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("zapier api error (status %d): %s", e.StatusCode, e.Body)
}

// ExecuteRequest describes an AI Action execution request.
type ExecuteRequest struct {
	ActionID     string
	Instructions string
	PreviewOnly  bool
	ParamsHints  map[string]any
}

// Client is a pooled Zapier AI Actions client.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new Zapier AI Actions client.
func NewClient(baseURL, apiKey string, timeout time.Duration) (*Client, error) {
	normalized, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, fmt.Errorf("zapier AI Actions API key required")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		baseURL: normalized,
		apiKey:  apiKey,
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

// ListActions lists stored AI actions for the authenticated user.
func (c *Client) ListActions(ctx context.Context, params map[string]any) (map[string]any, error) {
	query := url.Values{}
	if app := strings.TrimSpace(stringValue(params["app"])); app != "" {
		query.Set("app", app)
	}
	if actionType := strings.TrimSpace(stringValue(params["action_type"])); actionType != "" {
		query.Set("action_type", actionType)
	}
	if page := intValue(params["page"]); page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	if limit := intValue(params["limit"]); limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/ai-actions/", query, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExecuteAction runs a stored AI action by id, or the generic execution endpoint when no id is supplied.
func (c *Client) ExecuteAction(ctx context.Context, req ExecuteRequest) (map[string]any, error) {
	instructions := strings.TrimSpace(req.Instructions)
	if instructions == "" {
		return nil, fmt.Errorf("instruction is required")
	}
	body := map[string]any{
		"instructions": instructions,
		"preview_only": req.PreviewOnly,
	}
	if len(req.ParamsHints) > 0 {
		body["params_hints"] = req.ParamsHints
	}

	apiPath := "/execute/"
	actionID := strings.TrimSpace(req.ActionID)
	if actionID != "" {
		apiPath = "/ai-actions/" + url.PathEscape(actionID) + "/execute/"
	}

	var out map[string]any
	if err := c.doJSON(ctx, http.MethodPost, apiPath, nil, body, &out); err != nil {
		return nil, err
	}
	if actionID != "" && strings.TrimSpace(stringValue(out["action_id"])) == "" {
		out["action_id"] = actionID
	}
	return out, nil
}

// GetExecutionLog fetches a previous AI Action execution log.
func (c *Client) GetExecutionLog(ctx context.Context, executionLogID string) (map[string]any, error) {
	executionLogID = strings.TrimSpace(executionLogID)
	if executionLogID == "" {
		return nil, fmt.Errorf("execution_log_id required")
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/execute/log/"+url.PathEscape(executionLogID)+"/", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) doJSON(ctx context.Context, method, apiPath string, query url.Values, body any, out any) error {
	requestURL := c.baseURL + apiPath
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
	req.Header.Set(authHeader, "Bearer "+c.apiKey)
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
		return "", fmt.Errorf("zapier AI Actions base url required")
	}
	if strings.Contains(trimmed, "/api/") {
		return trimmed, nil
	}
	return trimmed + "/api/v2", nil
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
