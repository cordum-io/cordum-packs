package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const defaultScannerBuffer = 2 * 1024 * 1024

type Server struct {
	Name      string
	Transport string
	Command   string
	Args      []string
	URL       string
	Env       map[string]string
	Headers   map[string]string
}

type Session struct {
	client rpcClient
}

type rpcClient interface {
	Request(ctx context.Context, method string, params any) (*Response, error)
	Notify(ctx context.Context, method string, params any) error
	Close() error
}

func NewSession(ctx context.Context, server Server) (*Session, error) {
	switch strings.ToLower(strings.TrimSpace(server.Transport)) {
	case "stdio":
		client, err := newStdioClient(ctx, server)
		if err != nil {
			return nil, err
		}
		return &Session{client: client}, nil
	case "http":
		client, err := newHTTPClient(server)
		if err != nil {
			return nil, err
		}
		return &Session{client: client}, nil
	default:
		return nil, fmt.Errorf("unsupported transport: %s", server.Transport)
	}
}

func (s *Session) Initialize(ctx context.Context, protocolVersion string, clientInfo ClientInfo) (map[string]any, error) {
	params := map[string]any{
		"protocolVersion": protocolVersion,
		"clientInfo": map[string]any{
			"name":    clientInfo.Name,
			"version": clientInfo.Version,
		},
		"capabilities": map[string]any{},
	}
	resp, err := s.client.Request(ctx, "initialize", params)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("initialize failed: %s", resp.Error.Message)
	}
	var out map[string]any
	if len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, &out); err != nil {
			return nil, err
		}
	}
	_ = s.client.Notify(ctx, "notifications/initialized", map[string]any{})
	return out, nil
}

func (s *Session) Call(ctx context.Context, method string, params any) (any, error) {
	resp, err := s.client.Request(ctx, method, params)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("%s", resp.Error.Message)
	}
	if len(resp.Result) == 0 {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Session) CallRaw(ctx context.Context, method string, params any) (*Response, error) {
	return s.client.Request(ctx, method, params)
}

func (s *Session) Notify(ctx context.Context, method string, params any) error {
	return s.client.Notify(ctx, method, params)
}

func (s *Session) Close() error {
	return s.client.Close()
}

// stdio transport

type stdioClient struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	stderr  *bytes.Buffer
	mu      sync.Mutex
	nextID  int64
}

func newStdioClient(ctx context.Context, server Server) (*stdioClient, error) {
	if strings.TrimSpace(server.Command) == "" {
		return nil, fmt.Errorf("stdio command required")
	}
	cmd := exec.CommandContext(ctx, server.Command, server.Args...)
	cmd.Env = append(os.Environ(), formatEnv(server.Env)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), defaultScannerBuffer)
	return &stdioClient{cmd: cmd, stdin: stdin, scanner: scanner, stderr: stderr}, nil
}

func (c *stdioClient) Request(ctx context.Context, method string, params any) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	id := c.nextID
	req := Request{JSONRPC: "2.0", ID: id, Method: method, Params: params}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(c.stdin, "%s\n", payload); err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if !c.scanner.Scan() {
			if err := c.scanner.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("stdio closed: %s", strings.TrimSpace(c.stderr.String()))
		}
		line := strings.TrimSpace(c.scanner.Text())
		if line == "" {
			continue
		}
		var resp Response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			return nil, err
		}
		if resp.ID == nil {
			continue
		}
		if fmt.Sprint(resp.ID) == fmt.Sprint(id) {
			return &resp, nil
		}
	}
}

func (c *stdioClient) Notify(ctx context.Context, method string, params any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	req := Request{JSONRPC: "2.0", Method: method, Params: params}
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.stdin, "%s\n", payload)
	return err
}

func (c *stdioClient) Close() error {
	_ = c.stdin.Close()
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	return c.cmd.Wait()
}

func formatEnv(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	pairs := make([]string, 0, len(env))
	for key, value := range env {
		if strings.TrimSpace(key) == "" {
			continue
		}
		pairs = append(pairs, fmt.Sprintf("%s=%s", key, value))
	}
	return pairs
}

// http transport

type httpClient struct {
	baseURL string
	headers map[string]string
	client  *http.Client
	mu      sync.Mutex
	nextID  int64
}

func newHTTPClient(server Server) (*httpClient, error) {
	if strings.TrimSpace(server.URL) == "" {
		return nil, fmt.Errorf("http url required")
	}
	headers := map[string]string{}
	for key, value := range server.Headers {
		if strings.TrimSpace(key) == "" {
			continue
		}
		headers[key] = value
	}
	return &httpClient{
		baseURL: strings.TrimRight(server.URL, "/"),
		headers: headers,
		client:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (c *httpClient) Request(ctx context.Context, method string, params any) (*Response, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.mu.Unlock()
	payload, err := json.Marshal(Request{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("http transport error: %s", msg)
	}
	var out Response
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *httpClient) Notify(ctx context.Context, method string, params any) error {
	payload, err := json.Marshal(Request{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (c *httpClient) Close() error {
	return nil
}

func EncodeBasicAuth(username, password string) string {
	payload := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(payload))
}
