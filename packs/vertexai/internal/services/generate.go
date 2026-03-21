package services

import (
	"context"
	"fmt"

	aiplatform "cloud.google.com/go/aiplatform/apiv1"
	cloudpb "cloud.google.com/go/aiplatform/apiv1/aiplatformpb"

	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/vertexclient"
)

// GenerateService wraps Vertex AI Gemini generation operations.
type GenerateService struct {
	client              *aiplatform.PredictionClient
	projectID           string
	location            string
	maxTokensPerRequest int
}

// NewGenerateService creates a generation service.
func NewGenerateService(ctx context.Context, reqCfg vertexclient.RequestConfig) (*GenerateService, error) {
	client, err := aiplatform.NewPredictionClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create prediction client: %w", err)
	}
	return &GenerateService{
		client:              client,
		projectID:           reqCfg.ProjectID,
		location:            reqCfg.Location,
		maxTokensPerRequest: reqCfg.MaxTokensPerRequest,
	}, nil
}

// Close releases client resources.
func (s *GenerateService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// GenerateContent calls Vertex AI's GenerateContent API.
func (s *GenerateService) GenerateContent(ctx context.Context, params map[string]any) (any, error) {
	request, err := s.buildGenerateRequest(params)
	if err != nil {
		return nil, err
	}

	response, err := s.client.GenerateContent(ctx, request)
	if err != nil {
		return nil, err
	}

	result, err := protoToMap(response)
	if err != nil {
		return nil, err
	}
	result["token_usage"] = generateUsageMetadataToTokenUsage(response.GetUsageMetadata())
	if finishReason := finishReasonFromCandidates(result["candidates"]); finishReason != "" {
		result["finish_reason"] = finishReason
	}
	return result, nil
}

func (s *GenerateService) buildGenerateRequest(params map[string]any) (*cloudpb.GenerateContentRequest, error) {
	model := stringParam(params, "model")
	if model == "" {
		return nil, fmt.Errorf("model is required")
	}

	contents, err := contentsFromPromptOrMessages(params)
	if err != nil {
		return nil, err
	}

	systemInstruction, err := systemInstructionFromAny(params["system_instruction"])
	if err != nil {
		return nil, fmt.Errorf("system_instruction: %w", err)
	}
	generationConfig, err := generationConfigFromParams(params["generation_config"], s.maxTokensPerRequest)
	if err != nil {
		return nil, err
	}
	safetySettings, err := safetySettingsFromParams(params["safety_settings"])
	if err != nil {
		return nil, err
	}

	request := &cloudpb.GenerateContentRequest{
		Model:            modelResource(s.projectID, s.location, model),
		Contents:         contents,
		GenerationConfig: generationConfig,
	}
	if systemInstruction != nil {
		request.SystemInstruction = systemInstruction
	}
	if len(safetySettings) > 0 {
		request.SafetySettings = safetySettings
	}
	return request, nil
}

func finishReasonFromCandidates(value any) string {
	candidates, ok := value.([]any)
	if !ok || len(candidates) == 0 {
		return ""
	}
	first, ok := candidates[0].(map[string]any)
	if !ok {
		return ""
	}
	if finishReason, ok := first["finish_reason"].(string); ok {
		return finishReason
	}
	return ""
}
