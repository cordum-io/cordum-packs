package datadogapi

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
	appKey     string
	headers    map[string]string
	userAgent  string
	httpClient *http.Client
}

type Options struct {
	APIKey    string
	AppKey    string
	Headers   map[string]string
	UserAgent string
	Timeout   time.Duration
}

func NewClient(baseURL string, opts Options) *Client {
	client := &http.Client{Timeout: opts.Timeout}
	if client.Timeout == 0 {
		client.Timeout = 30 * time.Second
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     strings.TrimSpace(opts.APIKey),
		appKey:     strings.TrimSpace(opts.AppKey),
		headers:    opts.Headers,
		userAgent:  strings.TrimSpace(opts.UserAgent),
		httpClient: client,
	}
}

func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body any) (any, int, error) {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		payload = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	for key, val := range c.headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		req.Header.Set(key, val)
	}
	if c.apiKey != "" {
		req.Header.Set("DD-API-KEY", c.apiKey)
	}
	if c.appKey != "" {
		req.Header.Set("DD-APPLICATION-KEY", c.appKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	payloadResp := parsePayload(data)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := errorMessage(payloadResp, resp.Status)
		return payloadResp, resp.StatusCode, fmt.Errorf("datadog error: %s", msg)
	}
	return payloadResp, resp.StatusCode, nil
}

func parsePayload(data []byte) any {
	if len(data) == 0 {
		return nil
	}
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return strings.TrimSpace(string(data))
	}
	return payload
}

func errorMessage(payload any, fallback string) string {
	switch typed := payload.(type) {
	case map[string]any:
		if msg := readErrorField(typed, "errors"); msg != "" {
			return msg
		}
		if msg := readErrorField(typed, "error"); msg != "" {
			return msg
		}
		if msg := readErrorField(typed, "message"); msg != "" {
			return msg
		}
	}
	if fallback == "" {
		return "unknown error"
	}
	return fallback
}

func readErrorField(payload map[string]any, key string) string {
	val, ok := payload[key]
	if !ok {
		return ""
	}
	switch typed := val.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := item.(string); ok {
				trimmed := strings.TrimSpace(str)
				if trimmed != "" {
					parts = append(parts, trimmed)
				}
			}
		}
		return strings.Join(parts, "; ")
	case []string:
		return strings.Join(typed, "; ")
	default:
		return fmt.Sprintf("%v", typed)
	}
}
