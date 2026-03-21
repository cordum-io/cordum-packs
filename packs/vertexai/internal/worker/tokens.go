package worker

import (
	cloudpb "cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
)

// TokenUsage captures prompt/completion/total usage from Gemini responses.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ExtractTokenUsage returns normalized token usage metadata from a Vertex AI generation response.
func ExtractTokenUsage(response *cloudpb.GenerateContentResponse) TokenUsage {
	if response == nil || response.GetUsageMetadata() == nil {
		return TokenUsage{}
	}
	usage := response.GetUsageMetadata()
	return TokenUsage{
		PromptTokens:     int(usage.GetPromptTokenCount()),
		CompletionTokens: int(usage.GetCandidatesTokenCount()),
		TotalTokens:      int(usage.GetTotalTokenCount()),
	}
}
