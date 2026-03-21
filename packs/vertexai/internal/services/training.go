package services

import (
	"context"
	"fmt"
	"strings"

	aiplatform "cloud.google.com/go/aiplatform/apiv1"
	cloudpb "cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
	giterator "google.golang.org/api/iterator"

	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/vertexclient"
)

// TrainingService wraps Vertex AI training pipeline operations.
type TrainingService struct {
	client    *aiplatform.PipelineClient
	projectID string
	location  string
}

// NewTrainingService creates a training pipeline service.
func NewTrainingService(ctx context.Context, reqCfg vertexclient.RequestConfig) (*TrainingService, error) {
	client, err := aiplatform.NewPipelineClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create pipeline client: %w", err)
	}
	return &TrainingService{
		client:    client,
		projectID: reqCfg.ProjectID,
		location:  reqCfg.Location,
	}, nil
}

// Close releases client resources.
func (s *TrainingService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// CreatePipeline creates a training pipeline.
func (s *TrainingService) CreatePipeline(ctx context.Context, params map[string]any) (any, error) {
	request, err := s.buildCreateTrainingPipelineRequest(params)
	if err != nil {
		return nil, err
	}

	response, err := s.client.CreateTrainingPipeline(ctx, request)
	if err != nil {
		return nil, err
	}
	return protoToAny(response)
}

// GetPipeline fetches a training pipeline.
func (s *TrainingService) GetPipeline(ctx context.Context, params map[string]any) (any, error) {
	pipelineID := firstNonEmpty(stringParam(params, "pipeline_id"), stringParam(params, "name"))
	if pipelineID == "" {
		return nil, fmt.Errorf("pipeline_id or name is required")
	}

	response, err := s.client.GetTrainingPipeline(ctx, &cloudpb.GetTrainingPipelineRequest{
		Name: trainingPipelineResource(s.projectID, s.location, pipelineID),
	})
	if err != nil {
		return nil, err
	}
	return protoToAny(response)
}

// ListPipelines lists training pipelines.
func (s *TrainingService) ListPipelines(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")
	readMask, err := readMaskParam(params, "read_mask")
	if err != nil {
		return nil, err
	}

	request := &cloudpb.ListTrainingPipelinesRequest{
		Parent:    locationParent(s.projectID, s.location),
		Filter:    stringParam(params, "filter"),
		PageSize:  pageSize,
		PageToken: pageToken,
		ReadMask:  readMask,
	}

	iterator := s.client.ListTrainingPipelines(ctx, request)
	pager := giterator.NewPager(iterator, int(pageSize), pageToken)

	var pipelines []*cloudpb.TrainingPipeline
	nextPageToken, err := pager.NextPage(&pipelines)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(pipelines)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"pipelines":       mapped,
		"next_page_token": nextPageToken,
	}, nil
}

func (s *TrainingService) buildCreateTrainingPipelineRequest(params map[string]any) (*cloudpb.CreateTrainingPipelineRequest, error) {
	trainingTaskDefinition := stringParam(params, "training_task_definition")
	if trainingTaskDefinition == "" {
		return nil, fmt.Errorf("training_task_definition is required")
	}

	taskInputs, err := structValueFromAny(firstNonEmptyValue(params["training_task_inputs"], params["task_inputs"]))
	if err != nil {
		return nil, fmt.Errorf("invalid training_task_inputs: %w", err)
	}
	if taskInputs == nil {
		return nil, fmt.Errorf("training_task_inputs is required")
	}

	labels, err := mapStringStringParam(params, "labels")
	if err != nil {
		return nil, err
	}

	pipeline := &cloudpb.TrainingPipeline{
		DisplayName:            firstNonEmpty(stringParam(params, "display_name"), defaultDisplayName("vertex-training")),
		TrainingTaskDefinition: trainingTaskDefinition,
		TrainingTaskInputs:     taskInputs,
		Labels:                 labels,
	}

	if inputDataConfig := params["input_data_config"]; inputDataConfig != nil {
		value := &cloudpb.InputDataConfig{}
		if err := anyToProto(inputDataConfig, value); err != nil {
			return nil, fmt.Errorf("decode input_data_config: %w", err)
		}
		pipeline.InputDataConfig = value
	}
	if modelToUpload := params["model_to_upload"]; modelToUpload != nil {
		value := &cloudpb.Model{}
		if err := anyToProto(modelToUpload, value); err != nil {
			return nil, fmt.Errorf("decode model_to_upload: %w", err)
		}
		pipeline.ModelToUpload = value
	}
	if modelID := stringParam(params, "model_id"); modelID != "" {
		pipeline.ModelId = modelID
	}
	if parentModel := stringParam(params, "parent_model"); parentModel != "" {
		pipeline.ParentModel = parentModel
	}
	if encryptionSpec := params["encryption_spec"]; encryptionSpec != nil {
		value := &cloudpb.EncryptionSpec{}
		if err := anyToProto(encryptionSpec, value); err != nil {
			return nil, fmt.Errorf("decode encryption_spec: %w", err)
		}
		pipeline.EncryptionSpec = value
	}

	return &cloudpb.CreateTrainingPipelineRequest{
		Parent:           locationParent(s.projectID, s.location),
		TrainingPipeline: pipeline,
	}, nil
}

func firstNonEmptyValue(values ...any) any {
	for _, value := range values {
		if value == nil {
			continue
		}
		if text, ok := value.(string); ok && strings.TrimSpace(text) == "" {
			continue
		}
		return value
	}
	return nil
}
