// Package temporalclient provides an HTTP client for the Temporal Frontend API.
// Uses Temporal's HTTP API (available in Temporal Server 1.24+) to avoid
// the heavy go.temporal.io/sdk dependency tree.
package temporalclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cordum-io/cordum-packs/packs/temporal/internal/config"
)

// Client is an HTTP client for the Temporal Frontend API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	namespace  string
	apiKey     string
	identity   string
}

// NewClient creates a Temporal HTTP API client.
func NewClient(cfg config.Config) *Client {
	host := strings.TrimRight(cfg.TemporalHost, "/")
	if !strings.HasPrefix(host, "http") {
		host = "http://" + host
	}

	return &Client{
		baseURL:   host,
		namespace: cfg.Namespace,
		apiKey:    cfg.APIKey,
		identity:  cfg.Identity,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any) (map[string]any, int, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s%s", c.baseURL, c.namespace, path)
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode, fmt.Errorf("temporal API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if len(respBody) > 0 {
		if json.Unmarshal(respBody, &result) != nil {
			return map[string]any{"body": string(respBody)}, resp.StatusCode, nil
		}
	}
	return result, resp.StatusCode, nil
}

// StartWorkflow starts a new workflow execution.
func (c *Client) StartWorkflow(ctx context.Context, params map[string]any) (any, error) {
	wfType, _ := params["workflow_type"].(string)
	if wfType == "" {
		return nil, fmt.Errorf("workflow_type is required")
	}
	taskQueue, _ := params["task_queue"].(string)
	if taskQueue == "" {
		return nil, fmt.Errorf("task_queue is required")
	}

	body := map[string]any{
		"workflowType": map[string]any{"name": wfType},
		"taskQueue":    map[string]any{"name": taskQueue},
		"identity":     c.identity,
	}
	if wfID, ok := params["workflow_id"].(string); ok && wfID != "" {
		body["workflowId"] = wfID
	}
	if input := params["input"]; input != nil {
		inputJSON, _ := json.Marshal(input)
		body["input"] = map[string]any{"payloads": []map[string]any{{"data": string(inputJSON)}}}
	}

	result, _, err := c.doJSON(ctx, "POST", "/workflows", body)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SignalWorkflow signals a running workflow.
func (c *Client) SignalWorkflow(ctx context.Context, params map[string]any) (any, error) {
	wfID, _ := params["workflow_id"].(string)
	signalName, _ := params["signal_name"].(string)
	if wfID == "" || signalName == "" {
		return nil, fmt.Errorf("workflow_id and signal_name are required")
	}

	body := map[string]any{"signalName": signalName, "identity": c.identity}
	if input := params["input"]; input != nil {
		inputJSON, _ := json.Marshal(input)
		body["input"] = map[string]any{"payloads": []map[string]any{{"data": string(inputJSON)}}}
	}

	path := fmt.Sprintf("/workflows/%s/signal", wfID)
	result, _, err := c.doJSON(ctx, "POST", path, body)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// QueryWorkflow queries a workflow's state.
func (c *Client) QueryWorkflow(ctx context.Context, params map[string]any) (any, error) {
	wfID, _ := params["workflow_id"].(string)
	queryType, _ := params["query_type"].(string)
	if wfID == "" || queryType == "" {
		return nil, fmt.Errorf("workflow_id and query_type are required")
	}

	body := map[string]any{"query": map[string]any{"queryType": queryType}}
	path := fmt.Sprintf("/workflows/%s/query", wfID)
	result, _, err := c.doJSON(ctx, "POST", path, body)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DescribeWorkflow returns workflow execution details.
func (c *Client) DescribeWorkflow(ctx context.Context, params map[string]any) (any, error) {
	wfID, _ := params["workflow_id"].(string)
	if wfID == "" {
		return nil, fmt.Errorf("workflow_id is required")
	}
	path := fmt.Sprintf("/workflows/%s", wfID)
	result, _, err := c.doJSON(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// CancelWorkflow requests cancellation of a workflow.
func (c *Client) CancelWorkflow(ctx context.Context, params map[string]any) (any, error) {
	wfID, _ := params["workflow_id"].(string)
	if wfID == "" {
		return nil, fmt.Errorf("workflow_id is required")
	}
	body := map[string]any{"identity": c.identity}
	path := fmt.Sprintf("/workflows/%s/cancel", wfID)
	result, _, err := c.doJSON(ctx, "POST", path, body)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// TerminateWorkflow forcefully terminates a workflow.
func (c *Client) TerminateWorkflow(ctx context.Context, params map[string]any) (any, error) {
	wfID, _ := params["workflow_id"].(string)
	if wfID == "" {
		return nil, fmt.Errorf("workflow_id is required")
	}
	reason, _ := params["reason"].(string)
	body := map[string]any{"identity": c.identity, "reason": reason}
	path := fmt.Sprintf("/workflows/%s/terminate", wfID)
	result, _, err := c.doJSON(ctx, "POST", path, body)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListWorkflows lists workflow executions.
func (c *Client) ListWorkflows(ctx context.Context, params map[string]any) (any, error) {
	query := ""
	if q, ok := params["query"].(string); ok {
		query = "?query=" + q
	}
	result, _, err := c.doJSON(ctx, "GET", "/workflows"+query, nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}
