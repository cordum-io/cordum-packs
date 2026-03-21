package services

import (
	"testing"

	cloudpb "cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
)

func TestGenerateBuildRequestValidation(t *testing.T) {
	t.Parallel()

	svc := &GenerateService{projectID: "demo-project", location: "us-central1", maxTokensPerRequest: 256}

	_, err := svc.buildGenerateRequest(map[string]any{"prompt": "hello"})
	assertErrMsg(t, err, "model is required")

	_, err = svc.buildGenerateRequest(map[string]any{"model": "gemini-2.5-flash"})
	assertErrMsg(t, err, "prompt or messages is required")
}

func TestGenerateBuildRequestAppliesConfigAndLimits(t *testing.T) {
	t.Parallel()

	svc := &GenerateService{projectID: "demo-project", location: "us-central1", maxTokensPerRequest: 256}

	req, err := svc.buildGenerateRequest(map[string]any{
		"model":  "gemini-2.5-flash",
		"prompt": "hello world",
		"generation_config": map[string]any{
			"temperature": 0.4,
			"max_tokens":  128,
		},
		"safety_settings": []any{
			map[string]any{
				"category":  "HARM_CATEGORY_DANGEROUS_CONTENT",
				"threshold": "BLOCK_MEDIUM_AND_ABOVE",
			},
		},
	})
	if err != nil {
		t.Fatalf("buildGenerateRequest returned error: %v", err)
	}
	if req.GetModel() != "projects/demo-project/locations/us-central1/publishers/google/models/gemini-2.5-flash" {
		t.Fatalf("unexpected model resource: %q", req.GetModel())
	}
	if req.GetGenerationConfig().GetMaxOutputTokens() != 128 {
		t.Fatalf("unexpected max output tokens: %d", req.GetGenerationConfig().GetMaxOutputTokens())
	}
	if len(req.GetSafetySettings()) != 1 {
		t.Fatalf("expected one safety setting, got %d", len(req.GetSafetySettings()))
	}
}

func TestGenerateBuildRequestRejectsTokenLimitOverrun(t *testing.T) {
	t.Parallel()

	svc := &GenerateService{projectID: "demo-project", location: "us-central1", maxTokensPerRequest: 64}
	_, err := svc.buildGenerateRequest(map[string]any{
		"model":  "gemini-2.5-flash",
		"prompt": "hello world",
		"generation_config": map[string]any{
			"max_tokens": 128,
		},
	})
	assertErrMsg(t, err, "generation_config.max_tokens exceeds configured limit of 64")
}

func TestFinishReasonFromCandidates(t *testing.T) {
	t.Parallel()

	got := finishReasonFromCandidates([]any{
		map[string]any{"finish_reason": "STOP"},
	})
	if got != "STOP" {
		t.Fatalf("expected finish reason STOP, got %q", got)
	}
}

func TestGenerateUsageMetadataToTokenUsage(t *testing.T) {
	t.Parallel()

	usage := generateUsageMetadataToTokenUsage(&cloudpb.GenerateContentResponse_UsageMetadata{
		PromptTokenCount:     12,
		CandidatesTokenCount: 4,
		TotalTokenCount:      16,
	})
	if usage["prompt_tokens"] != 12 || usage["completion_tokens"] != 4 || usage["total_tokens"] != 16 {
		t.Fatalf("unexpected token usage: %+v", usage)
	}
}
