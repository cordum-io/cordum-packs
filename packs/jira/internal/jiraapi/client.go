package jiraapi

import (
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
	return fmt.Sprintf("jira api error (%d): %s", e.StatusCode, e.Message)
}

type Options struct {
	Headers   map[string]string
	UserAgent string
	Timeout   time.Duration
}

type Client struct {
	baseURL    string
	userAgent  string
	headers    map[string]string
	authHeader string
	httpClient *http.Client
}

func NewClient(baseURL, authHeader string, opts Options) *Client {
	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = "cordum-jira-worker"
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

	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		userAgent:  userAgent,
		headers:    headers,
		authHeader: strings.TrimSpace(authHeader),
		httpClient: &http.Client{Timeout: timeout},
	}
}

func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body any) (*Response, error) {
	endpoint := c.baseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	var req *http.Request
	var err error
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(string(payload)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return nil, err
		}
	}

	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var decoded any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &decoded); err != nil {
			decoded = strings.TrimSpace(string(data))
		}
	}

	response := &Response{
		StatusCode: resp.StatusCode,
		RequestID:  requestIDFromHeaders(resp.Header),
		Body:       decoded,
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := resp.Status
		if msg := jiraError(decoded); msg != "" {
			message = msg
		}
		return response, &APIError{StatusCode: resp.StatusCode, Message: message, Body: decoded}
	}

	if msg := jiraError(decoded); msg != "" {
		return response, &APIError{StatusCode: resp.StatusCode, Message: msg, Body: decoded}
	}

	return response, nil
}

func jiraError(decoded any) string {
	payload, ok := decoded.(map[string]any)
	if !ok {
		return ""
	}
	if msgs, ok := payload["errorMessages"].([]any); ok && len(msgs) > 0 {
		parts := make([]string, 0, len(msgs))
		for _, msg := range msgs {
			if text, ok := msg.(string); ok && strings.TrimSpace(text) != "" {
				parts = append(parts, text)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	}
	if errs, ok := payload["errors"].(map[string]any); ok && len(errs) > 0 {
		parts := make([]string, 0, len(errs))
		for key, val := range errs {
			if text, ok := val.(string); ok && strings.TrimSpace(text) != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", key, text))
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	}
	return ""
}

func requestIDFromHeaders(header http.Header) string {
	if val := strings.TrimSpace(header.Get("X-Request-Id")); val != "" {
		return val
	}
	if val := strings.TrimSpace(header.Get("X-Atlassian-Trace-Id")); val != "" {
		return val
	}
	return ""
}
