package worker

import (
	"testing"

	cloudpb "cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
)

func TestExtractTokenUsage(t *testing.T) {
	t.Run("nil response", func(t *testing.T) {
		got := ExtractTokenUsage(nil)
		if got != (TokenUsage{}) {
			t.Fatalf("expected zero token usage, got %+v", got)
		}
	})

	t.Run("maps usage metadata", func(t *testing.T) {
		response := &cloudpb.GenerateContentResponse{
			UsageMetadata: &cloudpb.GenerateContentResponse_UsageMetadata{
				PromptTokenCount:     123,
				CandidatesTokenCount: 45,
				TotalTokenCount:      168,
			},
		}

		got := ExtractTokenUsage(response)
		want := TokenUsage{
			PromptTokens:     123,
			CompletionTokens: 45,
			TotalTokens:      168,
		}
		if got != want {
			t.Fatalf("expected %+v, got %+v", want, got)
		}
	})
}
