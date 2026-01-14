package githubapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Response struct {
	StatusCode int
	RequestID  string
	RateLimit  map[string]string
	Body       any
}

type APIError struct {
	StatusCode int
	Message    string
	Body       any
}

func (e *APIError) Error() string {
	return fmt.Sprintf("github api error (%d): %s", e.StatusCode, e.Message)
}

type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

type StaticTokenProvider struct {
	TokenValue string
}

func (s StaticTokenProvider) Token(ctx context.Context) (string, error) {
	if strings.TrimSpace(s.TokenValue) == "" {
		return "", fmt.Errorf("github token required")
	}
	return s.TokenValue, nil
}

type AppTokenProvider struct {
	baseURL        string
	appID          string
	installationID string
	privateKey     *rsa.PrivateKey
	httpClient     *http.Client
	userAgent      string
	apiVersion     string

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func NewAppTokenProvider(baseURL, appID, installationID, privateKeyPEM, userAgent, apiVersion string, timeout time.Duration) (*AppTokenProvider, error) {
	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &AppTokenProvider{
		baseURL:        strings.TrimRight(baseURL, "/"),
		appID:          strings.TrimSpace(appID),
		installationID: strings.TrimSpace(installationID),
		privateKey:     key,
		httpClient:     &http.Client{Timeout: timeout},
		userAgent:      userAgent,
		apiVersion:     apiVersion,
	}, nil
}

func (p *AppTokenProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" && time.Until(p.expiresAt) > 2*time.Minute {
		return p.token, nil
	}

	jwtToken, err := buildJWT(p.appID, p.privateKey)
	if err != nil {
		return "", err
	}

	payload := map[string]any{}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/app/installations/%s/access_tokens", p.baseURL, url.PathEscape(p.installationID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	setDefaultHeaders(req.Header, p.userAgent, p.apiVersion)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	if len(data) > 0 {
		_ = json.Unmarshal(data, &decoded)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := resp.Status
		if msg, ok := decoded["message"].(string); ok && msg != "" {
			message = msg
		}
		return "", &APIError{StatusCode: resp.StatusCode, Message: message, Body: decoded}
	}

	token, _ := decoded["token"].(string)
	expiresRaw, _ := decoded["expires_at"].(string)
	if token == "" {
		return "", fmt.Errorf("github app token missing")
	}
	if expiresRaw != "" {
		if expiresAt, err := time.Parse(time.RFC3339, expiresRaw); err == nil {
			p.expiresAt = expiresAt
		}
	}
	if p.expiresAt.IsZero() {
		p.expiresAt = time.Now().Add(50 * time.Minute)
	}
	p.token = token
	return token, nil
}

type Options struct {
	Headers     map[string]string
	UserAgent   string
	APIVersion  string
	TokenType   string
	Timeout     time.Duration
	HTTPTimeout time.Duration
}

type Client struct {
	baseURL       string
	userAgent     string
	apiVersion    string
	headers       map[string]string
	tokenType     string
	tokenProvider TokenProvider
	httpClient    *http.Client
}

func NewClient(baseURL string, tokenProvider TokenProvider, opts Options) *Client {
	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = "cordum-github-worker"
	}
	apiVersion := strings.TrimSpace(opts.APIVersion)
	if apiVersion == "" {
		apiVersion = "2022-11-28"
	}
	tokenType := strings.TrimSpace(opts.TokenType)
	if tokenType == "" {
		tokenType = "Bearer"
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	clientTimeout := opts.HTTPTimeout
	if clientTimeout == 0 {
		clientTimeout = timeout
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
		apiVersion:    apiVersion,
		headers:       headers,
		tokenType:     tokenType,
		tokenProvider: tokenProvider,
		httpClient:    &http.Client{Timeout: clientTimeout},
	}
}

func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body any) (Response, error) {
	req, err := c.newRequest(ctx, method, path, query, body)
	if err != nil {
		return Response{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()

	payload, err := decodeBody(resp)
	if err != nil {
		return Response{}, err
	}

	response := Response{
		StatusCode: resp.StatusCode,
		RequestID:  firstHeader(resp.Header, "X-GitHub-Request-Id", "X-Github-Request-Id", "X-GitHub-Request-ID"),
		RateLimit:  rateLimitFromHeaders(resp.Header),
		Body:       payload,
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := resp.Status
		if msg := extractMessage(payload); msg != "" {
			message = msg
		}
		return response, &APIError{StatusCode: resp.StatusCode, Message: message, Body: payload}
	}
	return response, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body any) (*http.Request, error) {
	endpoint := c.baseURL + "/" + strings.TrimLeft(path, "/")
	if query != nil {
		encoded := query.Encode()
		if encoded != "" {
			endpoint += "?" + encoded
		}
	}

	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = strings.NewReader(string(data))
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return nil, err
	}

	setDefaultHeaders(req.Header, c.userAgent, c.apiVersion)
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	if c.tokenProvider != nil {
		token, err := c.tokenProvider.Token(ctx)
		if err != nil {
			return nil, err
		}
		if token != "" {
			req.Header.Set("Authorization", c.tokenType+" "+token)
		}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func setDefaultHeaders(headers http.Header, userAgent, apiVersion string) {
	headers.Set("Accept", "application/vnd.github+json")
	headers.Set("User-Agent", userAgent)
	if strings.TrimSpace(apiVersion) != "" {
		headers.Set("X-GitHub-Api-Version", apiVersion)
	}
}

func rateLimitFromHeaders(headers http.Header) map[string]string {
	mapping := map[string]string{
		"limit":     headers.Get("X-RateLimit-Limit"),
		"remaining": headers.Get("X-RateLimit-Remaining"),
		"reset":     headers.Get("X-RateLimit-Reset"),
		"used":      headers.Get("X-RateLimit-Used"),
		"resource":  headers.Get("X-RateLimit-Resource"),
	}
	out := map[string]string{}
	for key, value := range mapping {
		if strings.TrimSpace(value) != "" {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstHeader(headers http.Header, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(headers.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func decodeBody(resp *http.Response) (any, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var out any
		if err := json.Unmarshal(data, &out); err == nil {
			return out, nil
		}
	}
	return strings.TrimSpace(string(data)), nil
}

func extractMessage(payload any) string {
	if payload == nil {
		return ""
	}
	if body, ok := payload.(map[string]any); ok {
		if msg, ok := body["message"].(string); ok {
			return msg
		}
	}
	if msg, ok := payload.(string); ok {
		return msg
	}
	return ""
}

func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	key := normalizePrivateKey(raw)
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return parsed, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be RSA")
	}
	return rsaKey, nil
}

func normalizePrivateKey(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if strings.Contains(trimmed, "\\n") {
		trimmed = strings.ReplaceAll(trimmed, "\\n", "\n")
	}
	return trimmed
}

func buildJWT(appID string, key *rsa.PrivateKey) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": strings.TrimSpace(appID),
		"iat": now.Add(-30 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
	}
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims

	hash := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + encodedSignature, nil
}
