package gatewayclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is an HTTP client for the Cordum API Gateway.
// Used for tool governance: submitting governed jobs and polling results.
type Client struct {
	baseURL    string
	apiKey     string
	tenantID   string
	httpClient *http.Client
}

// JobSubmitRequest mirrors the gateway submit job payload.
type JobSubmitRequest struct {
	Prompt         string            `json:"prompt"`
	Topic          string            `json:"topic"`
	Context        any               `json:"context,omitempty"`
	TenantID       string            `json:"tenant_id,omitempty"`
	PackID         string            `json:"pack_id,omitempty"`
	Capability     string            `json:"capability,omitempty"`
	RiskTags       []string          `json:"risk_tags,omitempty"`
	Requires       []string          `json:"requires,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
}

// JobSubmitResponse captures the job submit response.
type JobSubmitResponse struct {
	JobID   string `json:"job_id"`
	TraceID string `json:"trace_id,omitempty"`
}

// New creates a new gateway client with connection pooling.
func New(baseURL, apiKey, tenantID string) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   apiKey,
		tenantID: strings.TrimSpace(tenantID),
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

// SubmitJob submits a governed job through the gateway for Safety Kernel evaluation.
func (c *Client) SubmitJob(ctx context.Context, req *JobSubmitRequest) (*JobSubmitResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	var resp JobSubmitResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/jobs", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetJob fetches a job record by ID for status polling.
func (c *Client) GetJob(ctx context.Context, jobID string) (map[string]any, error) {
	if jobID == "" {
		return nil, fmt.Errorf("job id required")
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/jobs/"+jobID, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		bodyReader = strings.NewReader(string(payload))
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.tenantID != "" {
		req.Header.Set("X-Tenant-ID", c.tenantID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("gateway error (status %d): %s", resp.StatusCode, msg)
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
