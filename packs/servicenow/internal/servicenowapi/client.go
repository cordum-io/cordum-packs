package servicenowapi

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
	token      string
	username   string
	password   string
	headers    map[string]string
	userAgent  string
	httpClient *http.Client
}

type Options struct {
	Token     string
	Username  string
	Password  string
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
		token:      strings.TrimSpace(opts.Token),
		username:   strings.TrimSpace(opts.Username),
		password:   opts.Password,
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
	req.Header.Set("Accept", "application/json")
	for key, val := range c.headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		req.Header.Set(key, val)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
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
		return payloadResp, resp.StatusCode, fmt.Errorf("servicenow error: %s", msg)
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
	case map[string]any:
		if msg, ok := typed["message"].(string); ok {
			return strings.TrimSpace(msg)
		}
		return fmt.Sprintf("%v", typed)
	default:
		return fmt.Sprintf("%v", typed)
	}
}
