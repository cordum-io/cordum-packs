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

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type StartRunOptions struct {
	OrgID          string
	TeamID         string
	DryRun         bool
	IdempotencyKey string
}

type StartRunResponse struct {
	RunID string `json:"run_id"`
}

func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) StartRun(ctx context.Context, workflowID string, payload any, opts StartRunOptions) (string, error) {
	if strings.TrimSpace(workflowID) == "" {
		return "", fmt.Errorf("workflow id required")
	}
	path := "/api/v1/workflows/" + url.PathEscape(strings.TrimSpace(workflowID)) + "/runs"
	query := url.Values{}
	if opts.OrgID != "" {
		query.Set("org_id", opts.OrgID)
	}
	if opts.TeamID != "" {
		query.Set("team_id", opts.TeamID)
	}
	if opts.DryRun {
		query.Set("dry_run", "true")
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if opts.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", opts.IdempotencyKey)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return "", fmt.Errorf("gateway error: %s", msg)
	}

	var decoded StartRunResponse
	if len(data) == 0 {
		return "", fmt.Errorf("gateway response missing run_id")
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return "", err
	}
	if decoded.RunID == "" {
		return "", fmt.Errorf("gateway response missing run_id")
	}
	return decoded.RunID, nil
}
