package services

import (
	"context"
	"fmt"

	aiplatform "cloud.google.com/go/aiplatform/apiv1"
	cloudpb "cloud.google.com/go/aiplatform/apiv1/aiplatformpb"

	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/vertexclient"
)

// EmbedService wraps Vertex AI embedding operations.
type EmbedService struct {
	client    *aiplatform.PredictionClient
	projectID string
	location  string
}

// NewEmbedService creates an embedding service.
func NewEmbedService(ctx context.Context, reqCfg vertexclient.RequestConfig) (*EmbedService, error) {
	client, err := aiplatform.NewPredictionClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create prediction client: %w", err)
	}
	return &EmbedService{
		client:    client,
		projectID: reqCfg.ProjectID,
		location:  reqCfg.Location,
	}, nil
}

// Close releases client resources.
func (s *EmbedService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// EmbedContent embeds one or more content items.
func (s *EmbedService) EmbedContent(ctx context.Context, params map[string]any) (any, error) {
	requests, err := s.buildEmbedRequests(params)
	if err != nil {
		return nil, err
	}

	responses := make([]map[string]any, 0, len(requests))
	embeddings := make([]any, 0, len(requests))
	totalPromptTokens := 0
	totalCompletionTokens := 0
	totalTokens := 0
	truncated := false

	for _, request := range requests {
		response, err := s.client.EmbedContent(ctx, request)
		if err != nil {
			return nil, err
		}

		mapped, err := protoToMap(response)
		if err != nil {
			return nil, err
		}
		responses = append(responses, mapped)
		if embedding, ok := mapped["embedding"]; ok {
			embeddings = append(embeddings, embedding)
		}

		usage := response.GetUsageMetadata()
		totalPromptTokens += int(usage.GetPromptTokenCount())
		totalCompletionTokens += int(usage.GetCandidatesTokenCount())
		totalTokens += int(usage.GetTotalTokenCount())
		truncated = truncated || response.GetTruncated()
	}

	return map[string]any{
		"embeddings":  embeddings,
		"responses":   responses,
		"truncated":   truncated,
		"token_usage": tokenUsageResult(totalPromptTokens, totalCompletionTokens, totalTokens),
	}, nil
}

func (s *EmbedService) buildEmbedRequests(params map[string]any) ([]*cloudpb.EmbedContentRequest, error) {
	model := stringParam(params, "model")
	if model == "" {
		return nil, fmt.Errorf("model is required")
	}

	rawContents, ok := params["contents"]
	if !ok || rawContents == nil {
		return nil, fmt.Errorf("contents are required")
	}
	items, ok := rawContents.([]any)
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("contents must be a non-empty array")
	}

	taskType, err := embeddingTaskType(stringParam(params, "task_type"))
	if err != nil {
		return nil, err
	}
	outputDimensionality, err := intParam(params, "output_dimensionality", 0)
	if err != nil {
		return nil, err
	}

	var autoTruncate *bool
	if _, ok := params["auto_truncate"]; ok {
		value, err := boolParam(params, "auto_truncate", false)
		if err != nil {
			return nil, err
		}
		autoTruncate = ptr(value)
	}

	requests := make([]*cloudpb.EmbedContentRequest, 0, len(items))
	for _, item := range items {
		content, err := embedContentFromAny(item)
		if err != nil {
			return nil, err
		}

		request := &cloudpb.EmbedContentRequest{
			Model:   ptr(modelResource(s.projectID, s.location, model)),
			Content: content,
		}
		if title := stringParam(params, "title"); title != "" {
			request.Title = ptr(title)
		}
		if taskType != cloudpb.EmbedContentRequest_UNSPECIFIED {
			request.TaskType = ptr(taskType)
		}
		if outputDimensionality > 0 {
			value := int32(outputDimensionality)
			request.OutputDimensionality = &value
		}
		if autoTruncate != nil {
			request.AutoTruncate = autoTruncate
		}

		requests = append(requests, request)
	}

	return requests, nil
}

func embedContentFromAny(value any) (*cloudpb.Content, error) {
	if message, ok := value.(map[string]any); ok {
		if content, exists := message["content"]; exists {
			return contentFromAny(stringParam(message, "role"), content)
		}
	}
	return contentFromAny("user", value)
}
