package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/config"
	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/vertexclient"
)

type dispatchRecorder struct {
	result  any
	err     error
	lastCfg vertexclient.RequestConfig
}

func (d *dispatchRecorder) Dispatch(_ context.Context, reqCfg vertexclient.RequestConfig, _ string, _ actionSpec, _ map[string]any) (any, error) {
	d.lastCfg = reqCfg
	return d.result, d.err
}

func TestActionSpecs(t *testing.T) {
	expectedActions := []string{
		actionPredict,
		actionRawPredict,
		actionCreateBatchJob,
		actionGetBatchJob,
		actionListBatchJobs,
		actionGenerateContent,
		actionEmbedContent,
		actionCreatePipeline,
		actionGetPipeline,
		actionListPipelines,
	}

	for _, action := range expectedActions {
		if _, ok := actionSpecs[action]; !ok {
			t.Errorf("missing action spec: %s", action)
		}
	}
	if len(actionSpecs) != len(expectedActions) {
		t.Fatalf("expected %d action specs, got %d", len(expectedActions), len(actionSpecs))
	}
}

func TestHandleJobRejectsDeniedModel(t *testing.T) {
	t.Parallel()

	recorder := &dispatchRecorder{}
	w := newTestWorker(recorder)
	w.cfg.Profiles["default"] = config.Profile{
		Name:                "default",
		ProjectID:           "demo-project",
		Location:            "us-central1",
		DeniedModels:        []string{"gemini-*"},
		MaxTokensPerRequest: 128,
	}

	result, err := w.handleJob(testRuntimeContext(topicGenerate), map[string]any{
		"action": actionGenerateContent,
		"params": map[string]any{
			"model":  "gemini-2.5-flash",
			"prompt": "hello",
		},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, "not allowed") {
		t.Fatalf("expected denied model error, got %+v", result)
	}
}

func TestHandleJobEnforcesTopic(t *testing.T) {
	t.Parallel()

	w := newTestWorker(&dispatchRecorder{})
	result, err := w.handleJob(testRuntimeContext(topicRead), map[string]any{
		"action": actionGenerateContent,
		"params": map[string]any{
			"model":  "gemini-2.5-flash",
			"prompt": "hello",
		},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, topicGenerate) {
		t.Fatalf("expected topic enforcement error, got %+v", result)
	}
}

func TestHandleJobEnforcesTokenLimit(t *testing.T) {
	t.Parallel()

	w := newTestWorker(&dispatchRecorder{})
	result, err := w.handleJob(testRuntimeContext(topicGenerate), map[string]any{
		"action": actionGenerateContent,
		"params": map[string]any{
			"model":  "gemini-2.5-flash",
			"prompt": "hello",
			"generation_config": map[string]any{
				"max_tokens": 999,
			},
		},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if !strings.Contains(result.Error, "configured limit") {
		t.Fatalf("expected token limit error, got %+v", result)
	}
}

func TestHandleJobCapturesTokenUsageAndCandidates(t *testing.T) {
	t.Parallel()

	recorder := &dispatchRecorder{result: map[string]any{
		"token_usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 5,
			"total_tokens":      15,
		},
		"candidates": []any{map[string]any{"finish_reason": "STOP"}},
	}}
	w := newTestWorker(recorder)

	result, err := w.handleJob(testRuntimeContext(topicGenerate), map[string]any{
		"action": actionGenerateContent,
		"params": map[string]any{
			"model":  "gemini-2.5-flash",
			"prompt": "hello",
		},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if result.StatusCode != 200 {
		t.Fatalf("expected success status, got %+v", result)
	}
	if result.TokenUsage == nil || result.TokenUsage.TotalTokens != 15 {
		t.Fatalf("expected token usage to be captured, got %+v", result.TokenUsage)
	}
	if result.FinishReason != "STOP" {
		t.Fatalf("expected finish reason STOP, got %q", result.FinishReason)
	}
	if recorder.lastCfg.MaxTokensPerRequest != 128 {
		t.Fatalf("expected resolved token limit 128, got %d", recorder.lastCfg.MaxTokensPerRequest)
	}
}

func TestNormalizeVertexError(t *testing.T) {
	t.Parallel()

	msg := normalizeVertexError(grpcstatus.Error(codes.NotFound, "missing endpoint"))
	if !strings.Contains(msg, "resource not found") {
		t.Fatalf("expected normalized not found error, got %q", msg)
	}
}

func newTestWorker(recorder *dispatchRecorder) *Worker {
	cfg := config.Config{
		RequestTimeout:      5 * time.Second,
		DefaultProjectID:    "demo-project",
		DefaultLocation:     "us-central1",
		DefaultProfile:      "default",
		MaxTokensPerRequest: 128,
		Profiles: map[string]config.Profile{
			"default": {
				Name:                "default",
				ProjectID:           "demo-project",
				Location:            "us-central1",
				AllowedModels:       []string{"gemini-*", "textembedding-gecko*", "projects/*"},
				MaxTokensPerRequest: 128,
			},
		},
	}
	return &Worker{
		cfg:      cfg,
		workerID: "worker-test",
		dispatch: recorder.Dispatch,
	}
}

func testRuntimeContext(topic string) runtime.Context {
	return runtime.Context{
		Job: &agentv1.JobRequest{
			JobId: "job-123",
			Topic: topic,
		},
		Packet: &agentv1.BusPacket{
			TraceId: "trace-123",
		},
	}
}
