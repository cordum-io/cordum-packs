package otelapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
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
	return fmt.Sprintf("opentelemetry api error (%d): %s", e.StatusCode, e.Message)
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
		userAgent = "cordum-opentelemetry-worker"
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
	endpoint, err := resolveEndpoint(c.baseURL, path, query)
	if err != nil {
		return nil, err
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

	resp, err := c.httpClient.Do(req) // #nosec G107 G704 -- endpoint is constrained to validated base URL and relative request path in resolveEndpoint
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
		if msg := messageFromValue(typed["error"]); msg != "" {
			return msg
		}
		if msg := messageFromValue(typed["message"]); msg != "" {
			return msg
		}
		if msg := messageFromValue(typed["errors"]); msg != "" {
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
	if val := strings.TrimSpace(header.Get("X-Request-Id")); val != "" {
		return val
	}
	if val := strings.TrimSpace(header.Get("X-Request-ID")); val != "" {
		return val
	}
	return ""
}

func resolveEndpoint(baseURL, endpointPath string, query url.Values) (string, error) {
	base, err := validateBaseURL(baseURL)
	if err != nil {
		return "", err
	}

	ref, err := parseRelativePath(endpointPath)
	if err != nil {
		return "", err
	}

	endpoint := *base
	endpoint.Path = joinURLPath(base.Path, ref.Path)
	endpoint.RawPath = ""

	values := ref.Query()
	for key, vals := range query {
		values.Del(key)
		for _, val := range vals {
			values.Add(key, val)
		}
	}
	endpoint.RawQuery = values.Encode()

	if endpoint.Scheme != base.Scheme || endpoint.Host != base.Host {
		return "", fmt.Errorf("endpoint host override is not allowed")
	}

	return endpoint.String(), nil
}

func validateBaseURL(raw string) (*url.URL, error) {
	base, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}
	if base == nil || base.Host == "" {
		return nil, fmt.Errorf("base url must include host")
	}
	scheme := strings.ToLower(strings.TrimSpace(base.Scheme))
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("base url scheme must be http or https")
	}
	if base.User != nil {
		return nil, fmt.Errorf("base url must not include credentials")
	}
	base.Scheme = scheme
	base.Fragment = ""
	base.RawFragment = ""
	base.RawQuery = ""
	return base, nil
}

func parseRelativePath(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("endpoint path is required")
	}
	if strings.HasPrefix(trimmed, "//") {
		return nil, fmt.Errorf("endpoint path must not override host")
	}
	ref, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint path: %w", err)
	}
	if ref.IsAbs() || ref.Host != "" {
		return nil, fmt.Errorf("endpoint path must be relative")
	}
	return ref, nil
}

func joinURLPath(basePath, relPath string) string {
	basePath = strings.TrimSuffix(basePath, "/")
	cleanRel := path.Clean("/" + strings.TrimPrefix(relPath, "/"))
	if cleanRel == "." {
		cleanRel = "/"
	}
	if basePath == "" || basePath == "/" {
		return cleanRel
	}
	return basePath + cleanRel
}
