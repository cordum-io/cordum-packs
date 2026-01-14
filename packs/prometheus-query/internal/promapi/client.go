package promapi

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

type Client struct {
	baseURL    string
	bearer     string
	basicUser  string
	basicPass  string
	headers    map[string]string
	userAgent  string
	httpClient *http.Client
}

type Response struct {
	Status    string   `json:"status"`
	Data      any      `json:"data"`
	Warnings  []string `json:"warnings"`
	ErrorType string   `json:"errorType"`
	Error     string   `json:"error"`
}

type Options struct {
	Headers   map[string]string
	UserAgent string
	Timeout   time.Duration
	Bearer    string
	BasicUser string
	BasicPass string
}

func NewClient(baseURL string, opts Options) *Client {
	client := &http.Client{Timeout: opts.Timeout}
	if client.Timeout == 0 {
		client.Timeout = 30 * time.Second
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		bearer:     strings.TrimSpace(opts.Bearer),
		basicUser:  strings.TrimSpace(opts.BasicUser),
		basicPass:  opts.BasicPass,
		headers:    opts.Headers,
		userAgent:  strings.TrimSpace(opts.UserAgent),
		httpClient: client,
	}
}

func (c *Client) Do(ctx context.Context, method, path string, params url.Values) (*Response, int, error) {
	endpoint := c.baseURL + path
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, 0, err
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
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	} else if c.basicUser != "" || c.basicPass != "" {
		req.SetBasicAuth(c.basicUser, c.basicPass)
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

	var payload Response
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	if payload.Status != "success" {
		msg := payload.Error
		if msg == "" {
			msg = fmt.Sprintf("prometheus error (%s)", payload.ErrorType)
		}
		return &payload, resp.StatusCode, fmt.Errorf("%s", msg)
	}
	return &payload, resp.StatusCode, nil
}
