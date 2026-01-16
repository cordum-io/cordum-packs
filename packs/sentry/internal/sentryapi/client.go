package sentryapi

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

type Response struct {
	StatusCode int
	RequestID  string
	Body       any
}

type APIError struct {
	StatusCode int
	Message    string
	Body       any
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sentry api error (%d): %s", e.StatusCode, e.Message)
}

type Options struct {
	Headers   map[string]string
	UserAgent string
	TokenType string
	Timeout   time.Duration
}

type Client struct {
	baseURL    string
	token      string
	userAgent  string
	headers    map[string]string
	tokenType  string
	httpClient *http.Client
}

func NewClient(baseURL, token string, opts Options) *Client {
	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = "cordum-sentry-worker"
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	headers := map[string]string{}
	for key, value := range opts.Headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers[key] = value
	}

	tokenType := strings.ToLower(strings.TrimSpace(opts.TokenType))
	if tokenType == "" {
		tokenType = "bearer"
	}

	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		token:      strings.TrimSpace(token),
		userAgent:  userAgent,
		headers:    headers,
		tokenType:  tokenType,
		httpClient: &http.Client{Timeout: timeout},
	}
}

func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body any) (*Response, error) {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	for key, val := range c.headers {
		req.Header.Set(key, val)
	}
	if c.token != "" {
		switch c.tokenType {
		case "bearer", "oauth", "oauth2", "token":
			req.Header.Set("Authorization", "Bearer "+c.token)
		default:
			req.Header.Set("Authorization", strings.TrimSpace(c.tokenType)+" "+c.token)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	payloadResp := parsePayload(data, resp.Header.Get("Content-Type"))
	response := &Response{
		StatusCode: resp.StatusCode,
		RequestID:  requestIDFromHeaders(resp.Header),
		Body:       payloadResp,
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := errorMessage(payloadResp)
		if msg == "" {
			msg = resp.Status
		}
		return response, &APIError{StatusCode: resp.StatusCode, Message: msg, Body: payloadResp}
	}

	if msg := errorMessage(payloadResp); msg != "" {
		return response, &APIError{StatusCode: resp.StatusCode, Message: msg, Body: payloadResp}
	}

	return response, nil
}

func parsePayload(data []byte, contentType string) any {
	if len(data) == 0 {
		return nil
	}
	if strings.Contains(contentType, "application/json") {
		var payload any
		if err := json.Unmarshal(data, &payload); err == nil {
			return payload
		}
	}
	return strings.TrimSpace(string(data))
}

func errorMessage(payload any) string {
	switch typed := payload.(type) {
	case map[string]any:
		if msg := messageFromValue(typed["detail"]); msg != "" {
			return msg
		}
		if msg := messageFromValue(typed["error"]); msg != "" {
			return msg
		}
		if msg := messageFromValue(typed["message"]); msg != "" {
			return msg
		}
	}
	return ""
}

func messageFromValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if msg := messageFromValue(item); msg != "" {
				parts = append(parts, msg)
			}
		}
		return strings.Join(parts, "; ")
	case map[string]any:
		parts := make([]string, 0, len(typed))
		for key, val := range typed {
			if msg := messageFromValue(val); msg != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", key, msg))
			}
		}
		return strings.Join(parts, "; ")
	default:
		if typed != nil {
			return fmt.Sprintf("%v", typed)
		}
	}
	return ""
}

func requestIDFromHeaders(header http.Header) string {
	if val := strings.TrimSpace(header.Get("X-Sentry-Request-Id")); val != "" {
		return val
	}
	if val := strings.TrimSpace(header.Get("X-Request-Id")); val != "" {
		return val
	}
	return ""
}
