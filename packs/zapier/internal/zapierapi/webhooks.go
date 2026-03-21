package zapierapi

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

// WebhookResponse captures a webhook dispatch result.
type WebhookResponse struct {
	Alias      string
	URL        string
	StatusCode int
	Body       any
}

// WebhookClient posts payloads to configured Zapier webhook aliases.
type WebhookClient struct {
	urls       map[string]string
	httpClient *http.Client
}

// NewWebhookClient creates a pooled webhook client.
func NewWebhookClient(urls map[string]string, timeout time.Duration) *WebhookClient {
	copied := make(map[string]string, len(urls))
	for key, value := range urls {
		copied[normalizeAlias(key)] = strings.TrimSpace(value)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &WebhookClient{
		urls: copied,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Send posts a JSON payload to a configured alias.
func (c *WebhookClient) Send(ctx context.Context, name string, payload map[string]any) (WebhookResponse, error) {
	alias := normalizeAlias(name)
	targetURL, ok := c.urls[alias]
	if !ok || strings.TrimSpace(targetURL) == "" {
		return WebhookResponse{}, fmt.Errorf("webhook %q not configured", name)
	}
	if payload == nil {
		payload = map[string]any{}
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return WebhookResponse{}, fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(data))
	if err != nil {
		return WebhookResponse{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return WebhookResponse{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	decoded := decodeBody(bodyBytes, resp.Header.Get("Content-Type"))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(bodyBytes))
		if message == "" {
			message = resp.Status
		}
		return WebhookResponse{}, &APIError{StatusCode: resp.StatusCode, Body: message}
	}
	return WebhookResponse{Alias: alias, URL: targetURL, StatusCode: resp.StatusCode, Body: decoded}, nil
}

func decodeBody(data []byte, contentType string) any {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	if strings.Contains(strings.ToLower(contentType), "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var decoded any
		if err := json.Unmarshal(data, &decoded); err == nil {
			return decoded
		}
	}
	return trimmed
}

func normalizeAlias(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
