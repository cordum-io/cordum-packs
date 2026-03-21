package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkclient "github.com/cordum/cordum/sdk/client"
	"github.com/nats-io/nats.go"
)

func TestCallbackServerApprovalFlow(t *testing.T) {
	t.Helper()

	gateway := &mockGatewayClient{
		submitResponse: &sdkclient.JobSubmitResponse{JobID: "job-123", TraceID: "trace-123"},
	}
	waiter := &mockJobWaiter{
		outcomes: map[string]*JobOutcome{
			"job-123": {
				Approved: true,
				Result:   map[string]any{"answer": "approved"},
				Status:   "succeeded",
			},
		},
	}

	server := newCallbackTestServer(t, gateway, waiter, 0)

	response := postToolCall(t, server, ToolCallRequest{
		ToolName:  "langchain.search",
		Arguments: map[string]any{"query": "cordum"},
	})

	if !response.Approved {
		t.Fatalf("expected tool call approval, got %#v", response)
	}
	if response.JobID != "job-123" {
		t.Fatalf("expected job id job-123, got %q", response.JobID)
	}
	if response.Status != "succeeded" {
		t.Fatalf("expected succeeded status, got %q", response.Status)
	}
	if got := gateway.lastSubmitRequest(); got.Topic != defaultToolCallTopic {
		t.Fatalf("expected default tool topic, got %q", got.Topic)
	}
	if got := gateway.lastSubmitRequest().Capability; got != "framework.langchain.search" {
		t.Fatalf("expected derived capability, got %q", got)
	}
	if got := gateway.lastSubmitRequest().Labels["tool_name"]; got != "langchain.search" {
		t.Fatalf("expected tool label, got %q", got)
	}
}

func TestCallbackServerDenialFlow(t *testing.T) {
	t.Helper()

	gateway := &mockGatewayClient{
		submitResponse: &sdkclient.JobSubmitResponse{JobID: "job-denied", TraceID: "trace-denied"},
	}
	waiter := &mockJobWaiter{
		outcomes: map[string]*JobOutcome{
			"job-denied": {
				Approved: false,
				Error:    "tool call requires human approval",
				Status:   "denied",
			},
		},
	}

	server := newCallbackTestServer(t, gateway, waiter, 0)

	response := postToolCall(t, server, ToolCallRequest{
		ToolName:  "crewai.deploy",
		Arguments: map[string]any{"env": "prod"},
	})

	if response.Approved {
		t.Fatalf("expected denial, got %#v", response)
	}
	if response.Error != "tool call requires human approval" {
		t.Fatalf("unexpected denial error %q", response.Error)
	}
	if response.Status != "denied" {
		t.Fatalf("expected denied status, got %q", response.Status)
	}
}

func TestCallbackServerConcurrentToolCalls(t *testing.T) {
	t.Helper()

	gateway := &mockGatewayClient{
		submitResponseFactory: func() *sdkclient.JobSubmitResponse {
			id := gatewayCounter.Add(1)
			return &sdkclient.JobSubmitResponse{JobID: fmt.Sprintf("job-%d", id), TraceID: fmt.Sprintf("trace-%d", id)}
		},
	}

	waiter := &mockJobWaiter{
		factory: func(jobID string) *JobOutcome {
			return &JobOutcome{
				Approved: true,
				Result:   map[string]any{"job_id": jobID},
				Status:   "succeeded",
			}
		},
	}

	server := newCallbackTestServer(t, gateway, waiter, 0)

	const count = 12
	var wg sync.WaitGroup
	results := make(chan ToolCallResponse, count)

	for index := 0; index < count; index++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- postToolCall(t, server, ToolCallRequest{
				ToolName:  "autogen.call",
				Arguments: map[string]any{"index": i},
				TraceID:   fmt.Sprintf("trace-%d", i),
			})
		}(index)
	}

	wg.Wait()
	close(results)

	seen := 0
	for result := range results {
		if !result.Approved {
			t.Fatalf("expected approval, got %#v", result)
		}
		seen++
	}
	if seen != count {
		t.Fatalf("expected %d responses, got %d", count, seen)
	}
	if got := gateway.submitCount.Load(); got != count {
		t.Fatalf("expected %d gateway submits, got %d", count, got)
	}
}

func TestCallbackServerTimeoutWhenJobNeverCompletes(t *testing.T) {
	t.Helper()

	gateway := &mockGatewayClient{
		submitResponse: &sdkclient.JobSubmitResponse{JobID: "job-timeout", TraceID: "trace-timeout"},
		jobResponseFactory: func(string) map[string]any {
			return map[string]any{"status": "running"}
		},
	}

	server := newCallbackTestServer(t, gateway, nil, 100*time.Millisecond)

	recorder := httptest.NewRecorder()
	requestBody := marshalJSON(t, ToolCallRequest{
		ToolName:  "llamaindex.retrieve",
		Arguments: map[string]any{"query": "timeout"},
	})
	request := httptest.NewRequest(http.MethodPost, "/tool-call", bytes.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")

	server.server.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 timeout, got %d", recorder.Code)
	}
	var response ToolCallResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode timeout response failed: %v", err)
	}
	if response.Approved {
		t.Fatalf("expected timeout denial")
	}
	if response.Status != "timeout" {
		t.Fatalf("expected timeout status, got %q", response.Status)
	}
}

type mockGatewayClient struct {
	submitResponse        *sdkclient.JobSubmitResponse
	submitResponseFactory func() *sdkclient.JobSubmitResponse
	jobResponseFactory    func(jobID string) map[string]any

	submitCount atomic.Int32
	mu          sync.Mutex
	submits     []*sdkclient.JobSubmitRequest
}

func (m *mockGatewayClient) SubmitJob(_ context.Context, req *sdkclient.JobSubmitRequest) (*sdkclient.JobSubmitResponse, error) {
	m.submitCount.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.submits = append(m.submits, req)
	if m.submitResponseFactory != nil {
		return m.submitResponseFactory(), nil
	}
	return m.submitResponse, nil
}

func (m *mockGatewayClient) GetJob(_ context.Context, jobID string) (map[string]any, error) {
	if m.jobResponseFactory != nil {
		return m.jobResponseFactory(jobID), nil
	}
	return map[string]any{"status": "succeeded", "result": map[string]any{"job_id": jobID}}, nil
}

func (m *mockGatewayClient) lastSubmitRequest() *sdkclient.JobSubmitRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.submits) == 0 {
		return nil
	}
	return m.submits[len(m.submits)-1]
}

type mockJobWaiter struct {
	outcomes map[string]*JobOutcome
	factory  func(jobID string) *JobOutcome
}

func (m *mockJobWaiter) Wait(ctx context.Context, jobID string) (*JobOutcome, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if m.factory != nil {
		return m.factory(jobID), nil
	}
	if outcome, ok := m.outcomes[jobID]; ok {
		return outcome, nil
	}
	return nil, fmt.Errorf("missing outcome for %s", jobID)
}

var gatewayCounter atomic.Int32

func newCallbackTestServer(t *testing.T, gateway GatewayClient, waiter JobWaiter, waitTimeout time.Duration) *CallbackServer {
	t.Helper()

	server, err := NewCallbackServer(CallbackConfig{
		GatewayClient:      gateway,
		NATSConn:           &nats.Conn{},
		CapabilityPrefix:   "framework",
		DefaultRiskTags:    []string{"tool", "governance"},
		DefaultRequires:    []string{"network:egress"},
		WaitTimeout:        waitTimeout,
		PollInterval:       10 * time.Millisecond,
		CustomResultWaiter: waiter,
	})
	if err != nil {
		t.Fatalf("new callback server failed: %v", err)
	}
	return server
}

func postToolCall(t *testing.T, server *CallbackServer, payload ToolCallRequest) ToolCallResponse {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tool-call", bytes.NewReader(marshalJSON(t, payload)))
	request.Header.Set("Content-Type", "application/json")

	server.server.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected HTTP status %d: %s", recorder.Code, recorder.Body.String())
	}

	var response ToolCallResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	return response
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	return data
}
