package gatewayclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

func New(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		APIKey:  strings.TrimSpace(apiKey),
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) PutArtifact(ctx context.Context, content []byte, contentType, retention string, labels map[string]string, maxBytes int64) (string, int, error) {
	payload := map[string]any{
		"content_base64": base64.StdEncoding.EncodeToString(content),
		"content_type":   strings.TrimSpace(contentType),
		"retention":      strings.TrimSpace(retention),
		"labels":         labels,
	}
	var resp struct {
		ArtifactPtr string `json:"artifact_ptr"`
		SizeBytes   int    `json:"size_bytes"`
	}
	headers := map[string]string{}
	if maxBytes > 0 {
		headers["X-Max-Artifact-Bytes"] = fmt.Sprintf("%d", maxBytes)
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/artifacts", payload, &resp, headers); err != nil {
		return "", 0, err
	}
	if resp.ArtifactPtr == "" {
		return "", 0, fmt.Errorf("artifact ptr missing from response")
	}
	return resp.ArtifactPtr, resp.SizeBytes, nil
}

func (c *Client) GetArtifact(ctx context.Context, ptr string) ([]byte, map[string]any, error) {
	escaped := url.PathEscape(ptr)
	var resp struct {
		ArtifactPtr   string         `json:"artifact_ptr"`
		ContentBase64 string         `json:"content_base64"`
		Metadata      map[string]any `json:"metadata"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/artifacts/"+escaped, nil, &resp, nil); err != nil {
		return nil, nil, err
	}
	data, err := base64.StdEncoding.DecodeString(resp.ContentBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode artifact: %w", err)
	}
	return data, resp.Metadata, nil
}

func (c *Client) StartRun(ctx context.Context, workflowID string, payload map[string]any, idempotencyKey string) (string, error) {
	escaped := url.PathEscape(workflowID)
	headers := map[string]string{}
	if strings.TrimSpace(idempotencyKey) != "" {
		headers["Idempotency-Key"] = idempotencyKey
	}
	var resp struct {
		RunID string `json:"run_id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/workflows/"+escaped+"/runs", payload, &resp, headers); err != nil {
		return "", err
	}
	if resp.RunID == "" {
		return "", fmt.Errorf("run_id missing from response")
	}
	return resp.RunID, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any, headers map[string]string) error {
	var buf io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		buf = bytes.NewBuffer(data)
	}
	urlStr := c.BaseURL + path
	if c.BaseURL == "" {
		urlStr = path
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, buf)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("gateway %s %s: %s", method, path, msg)
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
