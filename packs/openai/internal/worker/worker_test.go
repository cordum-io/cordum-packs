package worker

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"

	"github.com/cordum-io/cordum-packs/packs/openai/internal/config"
	"github.com/cordum-io/cordum-packs/packs/openai/internal/openaiapi"
)

type fakeClient struct {
	lastChatRequest openaiapi.ChatCompletionRequest
	chatResponse    openaiapi.JSONResponse
	chatError       error
}

func (f *fakeClient) ChatCompletion(_ context.Context, req openaiapi.ChatCompletionRequest) (openaiapi.JSONResponse, error) {
	f.lastChatRequest = req
	if f.chatResponse.StatusCode == 0 {
		f.chatResponse.StatusCode = 200
	}
	return f.chatResponse, f.chatError
}

func (f *fakeClient) ChatCompletionStream(_ context.Context, req openaiapi.ChatCompletionRequest) (openaiapi.StreamResponse, error) {
	f.lastChatRequest = req
	return openaiapi.StreamResponse{
		StatusCode: 200,
		Body: io.NopCloser(strings.NewReader(strings.Join([]string{
			`data: {"choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}]}`,
			"",
			`data: {"choices":[],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`,
			"",
			`data: [DONE]`,
			"",
		}, "\n"))),
	}, nil
}

func (f *fakeClient) CreateEmbedding(_ context.Context, _ openaiapi.EmbeddingRequest) (openaiapi.JSONResponse, error) {
	return openaiapi.JSONResponse{StatusCode: 200}, nil
}

func (f *fakeClient) GenerateImage(_ context.Context, _ openaiapi.ImageGenerateRequest) (openaiapi.JSONResponse, error) {
	return openaiapi.JSONResponse{StatusCode: 200}, nil
}

func (f *fakeClient) TranscribeAudio(_ context.Context, _ openaiapi.AudioTranscribeRequest) (openaiapi.JSONResponse, error) {
	return openaiapi.JSONResponse{StatusCode: 200}, nil
}

func (f *fakeClient) TextToSpeech(_ context.Context, _ openaiapi.AudioSpeechRequest) (openaiapi.BinaryResponse, error) {
	return openaiapi.BinaryResponse{StatusCode: 200, Data: []byte("audio")}, nil
}

func (f *fakeClient) CreateFineTune(_ context.Context, _ openaiapi.FineTuneCreateRequest) (openaiapi.JSONResponse, error) {
	return openaiapi.JSONResponse{StatusCode: 200}, nil
}

func (f *fakeClient) ListFineTunes(_ context.Context) (openaiapi.JSONResponse, error) {
	return openaiapi.JSONResponse{StatusCode: 200}, nil
}

func (f *fakeClient) GetFineTune(_ context.Context, _ string) (openaiapi.JSONResponse, error) {
	return openaiapi.JSONResponse{StatusCode: 200}, nil
}

func (f *fakeClient) CancelFineTune(_ context.Context, _ string) (openaiapi.JSONResponse, error) {
	return openaiapi.JSONResponse{StatusCode: 200}, nil
}

func (f *fakeClient) ListModels(_ context.Context) (openaiapi.JSONResponse, error) {
	return openaiapi.JSONResponse{StatusCode: 200}, nil
}

func TestHandleJobRejectsDeniedModel(t *testing.T) {
	t.Parallel()

	client := &fakeClient{}
	w := newTestWorker(client)
	w.cfg.Profiles["default"] = config.Profile{
		Name:           "default",
		APIKey:         "test-key",
		BaseURL:        "https://api.openai.com/v1",
		DeniedModels:   []string{"gpt-4o"},
		CostTracking:   boolPtr(true),
		RateLimitRetry: boolPtr(true),
		MaxRetries:     intPtr(1),
	}

	_, err := w.handleJob(testRuntimeContext("job.openai.chat"), map[string]any{
		"action":   actionChatCompletions,
		"model":    "gpt-4o",
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
	})
	if err == nil || !strings.Contains(err.Error(), "model denied") {
		t.Fatalf("expected denied model error, got %v", err)
	}
}

func TestHandleJobCapsMaxTokens(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		chatResponse: openaiapi.JSONResponse{
			StatusCode: 200,
			Body:       map[string]any{"model": "gpt-4o"},
		},
	}
	w := newTestWorker(client)
	w.cfg.Profiles["default"] = config.Profile{
		Name:           "default",
		APIKey:         "test-key",
		BaseURL:        "https://api.openai.com/v1",
		MaxTokensLimit: 128,
		CostTracking:   boolPtr(true),
		RateLimitRetry: boolPtr(true),
		MaxRetries:     intPtr(1),
	}

	_, err := w.handleJob(testRuntimeContext("job.openai.chat"), map[string]any{
		"action":     actionChatCompletions,
		"model":      "gpt-4o",
		"messages":   []map[string]any{{"role": "user", "content": "hello"}},
		"max_tokens": 999,
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if client.lastChatRequest.MaxTokens != 128 {
		t.Fatalf("max tokens = %d, want 128", client.lastChatRequest.MaxTokens)
	}
}

func TestHandleJobEnforcesTopicIntent(t *testing.T) {
	t.Parallel()

	w := newTestWorker(&fakeClient{})
	_, err := w.handleJob(testRuntimeContext("job.openai.chat"), map[string]any{
		"action": actionImagesGenerate,
		"model":  "dall-e-3",
		"prompt": "draw a cat",
	})
	if err == nil || !strings.Contains(err.Error(), "job.openai.image.generate") {
		t.Fatalf("expected topic enforcement error, got %v", err)
	}
}

func TestHandleJobValidatesParameters(t *testing.T) {
	t.Parallel()

	w := newTestWorker(&fakeClient{})
	_, err := w.handleJob(testRuntimeContext("job.openai.chat"), map[string]any{
		"action": actionChatCompletions,
		"model":  "gpt-4o",
	})
	if err == nil || !strings.Contains(err.Error(), "messages required") {
		t.Fatalf("expected messages required error, got %v", err)
	}
}

func TestHandleJobTracksCostInResults(t *testing.T) {
	t.Parallel()

	client := &fakeClient{
		chatResponse: openaiapi.JSONResponse{
			StatusCode: 200,
			Body:       map[string]any{"model": "gpt-4o", "choices": []any{}},
			Usage: openaiapi.Usage{
				PromptTokens:     1000,
				CompletionTokens: 500,
				TotalTokens:      1500,
			},
		},
	}
	w := newTestWorker(client)

	result, err := w.handleJob(testRuntimeContext("job.openai.chat"), map[string]any{
		"action":   actionChatCompletions,
		"model":    "gpt-4o",
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
	})
	if err != nil {
		t.Fatalf("handleJob error = %v", err)
	}
	if result.Usage.TotalTokens != 1500 {
		t.Fatalf("usage total tokens = %d", result.Usage.TotalTokens)
	}
	if result.CostEstimate <= 0 {
		t.Fatalf("expected positive cost estimate, got %f", result.CostEstimate)
	}
}

func newTestWorker(client *fakeClient) *Worker {
	cfg := config.Config{
		RequestTimeout: 5 * time.Second,
		DefaultProfile: "default",
		CostTracking:   true,
		RateLimitRetry: true,
		MaxRetries:     1,
		Profiles: map[string]config.Profile{
			"default": {
				Name:           "default",
				BaseURL:        "https://api.openai.com/v1",
				APIKey:         "test-key",
				AllowedModels:  []string{"gpt-*", "dall-e-*", "text-embedding-*"},
				CostTracking:   boolPtr(true),
				RateLimitRetry: boolPtr(true),
				MaxRetries:     intPtr(1),
			},
		},
	}
	return &Worker{
		cfg:      cfg,
		workerID: "worker-test",
		newClient: func(profile config.Profile) openAIClient {
			return client
		},
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

func boolPtr(v bool) *bool {
	return &v
}

func intPtr(v int) *int {
	return &v
}
