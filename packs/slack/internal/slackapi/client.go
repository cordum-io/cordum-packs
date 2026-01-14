package slackapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Response struct {
	StatusCode int
	RequestID  string
	RetryAfter int
	Body       any
	OK         bool
	Error      string
}

type APIError struct {
	StatusCode int
	Message    string
	Body       any
}

func (e *APIError) Error() string {
	return fmt.Sprintf("slack api error (%d): %s", e.StatusCode, e.Message)
}

type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

type StaticTokenProvider struct {
	TokenValue string
}

func (s StaticTokenProvider) Token(ctx context.Context) (string, error) {
	if strings.TrimSpace(s.TokenValue) == "" {
		return "", fmt.Errorf("slack token required")
	}
	return s.TokenValue, nil
}

type Options struct {
	Headers   map[string]string
	UserAgent string
	Timeout   time.Duration
}

type Client struct {
	baseURL       string
	userAgent     string
	headers       map[string]string
	tokenProvider TokenProvider
	httpClient    *http.Client
}

func NewClient(baseURL string, tokenProvider TokenProvider, opts Options) *Client {
	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = "cordum-slack-worker"
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
		baseURL:       strings.TrimRight(baseURL, "/"),
		userAgent:     userAgent,
		headers:       headers,
		tokenProvider: tokenProvider,
		httpClient:    &http.Client{Timeout: timeout},
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
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return nil, err
		}
	}

	token, err := c.tokenProvider.Token(ctx)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", c.userAgent)
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

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
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		Body:       decoded,
		OK:         true,
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := resp.Status
		if msg := slackError(decoded); msg != "" {
			message = msg
		}
		response.OK = false
		response.Error = message
		return response, &APIError{StatusCode: resp.StatusCode, Message: message, Body: decoded}
	}

	if ok, msg := slackOK(decoded); !ok {
		response.OK = false
		response.Error = msg
		return response, &APIError{StatusCode: resp.StatusCode, Message: msg, Body: decoded}
	}

	return response, nil
}

func slackOK(decoded any) (bool, string) {
	payload, ok := decoded.(map[string]any)
	if !ok {
		return true, ""
	}
	okValue, hasOK := payload["ok"].(bool)
	if !hasOK {
		return true, ""
	}
	if okValue {
		return true, ""
	}
	if msg, ok := payload["error"].(string); ok && msg != "" {
		return false, msg
	}
	return false, "slack api error"
}

func slackError(decoded any) string {
	payload, ok := decoded.(map[string]any)
	if !ok {
		return ""
	}
	if msg, ok := payload["error"].(string); ok {
		return msg
	}
	return ""
}

func requestIDFromHeaders(header http.Header) string {
	if val := strings.TrimSpace(header.Get("X-Slack-Req-Id")); val != "" {
		return val
	}
	if val := strings.TrimSpace(header.Get("X-Request-Id")); val != "" {
		return val
	}
	return ""
}

func parseRetryAfter(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	if val, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return val
	}
	return 0
}
