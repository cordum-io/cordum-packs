package picclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VerifyRequest is the JSON body sent to POST /verify.
type VerifyRequest struct {
	ToolName string         `json:"tool_name"`
	ToolArgs map[string]any `json:"tool_args,omitempty"`
}

// VerifyResponse is the JSON body returned by POST /verify.
type VerifyResponse struct {
	Allowed bool         `json:"allowed"`
	EvalMs  int          `json:"eval_ms"`
	Error   *VerifyError `json:"error,omitempty"`
}

// VerifyError is the nested error object when allowed=false.
type VerifyError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Client is a fail-closed HTTP client for the PIC bridge.
type Client struct {
	baseURL    string
	timeout    time.Duration
	authToken  string
	httpClient *http.Client
}

// New creates a PIC bridge client. If authToken is non-empty, all requests
// include an Authorization: Bearer header.
func New(baseURL string, timeout time.Duration, authToken string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		timeout:    timeout,
		authToken:  authToken,
		httpClient: &http.Client{},
	}
}

// VerifyToolCall calls POST /verify on the PIC bridge.
// Fail-closed: any error returns allowed=false with PIC_BRIDGE_UNREACHABLE.
func (c *Client) VerifyToolCall(ctx context.Context, toolName string, toolArgs map[string]any) VerifyResponse {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	start := time.Now()

	failClosed := func(msg string) VerifyResponse {
		return VerifyResponse{
			Allowed: false,
			EvalMs:  int(time.Since(start).Milliseconds()),
			Error: &VerifyError{
				Code:    "PIC_BRIDGE_UNREACHABLE",
				Message: msg,
			},
		}
	}

	if strings.TrimSpace(toolName) == "" {
		return failClosed("invalid request: empty tool_name")
	}

	body, err := json.Marshal(VerifyRequest{
		ToolName: toolName,
		ToolArgs: toolArgs,
	})
	if err != nil {
		return failClosed(fmt.Sprintf("marshal request: %v", err))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/verify", bytes.NewReader(body))
	if err != nil {
		return failClosed(fmt.Sprintf("create request: %v", err))
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return failClosed(fmt.Sprintf("bridge call failed: %v", err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return failClosed(fmt.Sprintf("read response: %v", err))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := string(respBody)
		if len(msg) > 512 {
			msg = msg[:512] + "...(truncated)"
		}
		return failClosed(fmt.Sprintf("bridge returned HTTP %d: %s", resp.StatusCode, msg))
	}

	var result VerifyResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return failClosed(fmt.Sprintf("malformed response: %v", err))
	}

	// Validate response consistency
	if !result.Allowed && result.Error == nil {
		return failClosed("malformed response: allowed=false but error missing")
	}
	if result.Allowed && result.Error != nil {
		return failClosed("malformed response: allowed=true but error present")
	}

	// Override eval_ms with client-side measurement for consistency
	result.EvalMs = int(time.Since(start).Milliseconds())
	return result
}

// HealthCheck calls GET /health on the PIC bridge.
// Returns nil if healthy, or an error describing the failure.
func (c *Client) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("create health request: %w", err)
	}
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("bridge unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("bridge health returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var health struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return fmt.Errorf("malformed health response: %w", err)
	}
	if health.Status != "ok" {
		return fmt.Errorf("bridge health status: %q", health.Status)
	}

	return nil
}
