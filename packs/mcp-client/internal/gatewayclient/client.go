package gatewayclient

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

type Client struct {
	baseURL    string
	apiKey     string
	tenantID   string
	httpClient *http.Client
}

type MemoryPayload struct {
	Pointer string `json:"pointer"`
	JSON    any    `json:"json"`
}

func New(baseURL, apiKey, tenantID string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		tenantID:   strings.TrimSpace(tenantID),
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (c *Client) GetMemory(ctx context.Context, ptr string) (*MemoryPayload, error) {
	if strings.TrimSpace(ptr) == "" {
		return nil, fmt.Errorf("memory ptr required")
	}
	path := "/api/v1/memory?ptr=" + url.QueryEscape(ptr)
	var resp MemoryPayload
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	endpoint, err := resolveEndpoint(c.baseURL, path)
	if err != nil {
		return err
	}

	var req *http.Request
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		req, err = http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return err
		}
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.tenantID != "" {
		req.Header.Set("X-Tenant-ID", c.tenantID)
	}
	resp, err := c.httpClient.Do(req) // #nosec G107 G704 -- endpoint is constrained to validated base URL and relative request path in resolveEndpoint
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("gateway error: %s", msg)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func resolveEndpoint(baseURL, requestPath string) (string, error) {
	base, err := validateBaseURL(baseURL)
	if err != nil {
		return "", err
	}

	ref, err := parseRelativePath(requestPath)
	if err != nil {
		return "", err
	}

	endpoint := *base
	endpoint.Path = joinURLPath(base.Path, ref.Path)
	endpoint.RawPath = ""
	endpoint.RawQuery = ref.RawQuery

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
		return nil, fmt.Errorf("request path is required")
	}
	if strings.HasPrefix(trimmed, "//") {
		return nil, fmt.Errorf("request path must not override host")
	}
	ref, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid request path: %w", err)
	}
	if ref.IsAbs() || ref.Host != "" {
		return nil, fmt.Errorf("request path must be relative")
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
