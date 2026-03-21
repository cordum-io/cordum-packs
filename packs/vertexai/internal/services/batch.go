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

// BatchService wraps Vertex AI batch prediction job operations.
type BatchService struct {
	client    *aiplatform.JobClient
	projectID string
	location  string
}

// NewBatchService creates a batch prediction service.
func NewBatchService(ctx context.Context, reqCfg vertexclient.RequestConfig) (*BatchService, error) {
	client, err := aiplatform.NewJobClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create job client: %w", err)
	}
	return &BatchService{
		client:    client,
		projectID: reqCfg.ProjectID,
		location:  reqCfg.Location,
	}, nil
}

// Close releases client resources.
func (s *BatchService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// CreatePredictionJob creates a batch prediction job.
func (s *BatchService) CreatePredictionJob(ctx context.Context, params map[string]any) (any, error) {
	request, err := s.buildCreatePredictionJobRequest(params)
	if err != nil {
		return nil, err
	}

	response, err := s.client.CreateBatchPredictionJob(ctx, request)
	if err != nil {
		return nil, err
	}
	return protoToAny(response)
}

// GetPredictionJob fetches a batch prediction job.
func (s *BatchService) GetPredictionJob(ctx context.Context, params map[string]any) (any, error) {
	jobID := firstNonEmpty(stringParam(params, "job_id"), stringParam(params, "name"))
	if jobID == "" {
		return nil, fmt.Errorf("job_id or name is required")
	}

	response, err := s.client.GetBatchPredictionJob(ctx, &cloudpb.GetBatchPredictionJobRequest{
		Name: batchJobResource(s.projectID, s.location, jobID),
	})
	if err != nil {
		return nil, err
	}
	return protoToAny(response)
}

// ListPredictionJobs lists batch prediction jobs.
func (s *BatchService) ListPredictionJobs(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")
	readMask, err := readMaskParam(params, "read_mask")
	if err != nil {
		return nil, err
	}

	request := &cloudpb.ListBatchPredictionJobsRequest{
		Parent:    locationParent(s.projectID, s.location),
		Filter:    stringParam(params, "filter"),
		PageSize:  pageSize,
		PageToken: pageToken,
		ReadMask:  readMask,
	}

	iterator := s.client.ListBatchPredictionJobs(ctx, request)
	pager := giterator.NewPager(iterator, int(pageSize), pageToken)

	var jobs []*cloudpb.BatchPredictionJob
	nextPageToken, err := pager.NextPage(&jobs)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(jobs)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"jobs":            mapped,
		"next_page_token": nextPageToken,
	}, nil
}

func (s *BatchService) buildCreatePredictionJobRequest(params map[string]any) (*cloudpb.CreateBatchPredictionJobRequest, error) {
	model := stringParam(params, "model")
	if model == "" {
		return nil, fmt.Errorf("model is required")
	}
	inputURI := stringParam(params, "input_uri")
	if inputURI == "" {
		return nil, fmt.Errorf("input_uri is required")
	}
	outputURI := stringParam(params, "output_uri")
	if outputURI == "" {
		return nil, fmt.Errorf("output_uri is required")
	}

	inputConfig, err := buildBatchInputConfig(inputURI, firstNonEmpty(stringParam(params, "instances_format"), inferBatchFormat(inputURI, "jsonl")))
	if err != nil {
		return nil, err
	}
	outputConfig, err := buildBatchOutputConfig(outputURI, firstNonEmpty(stringParam(params, "predictions_format"), inferBatchFormat(outputURI, "jsonl")))
	if err != nil {
		return nil, err
	}
	modelParameters, err := structValueFromAny(params["parameters"])
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	labels, err := mapStringStringParam(params, "labels")
	if err != nil {
		return nil, err
	}
	dedicatedResources, err := buildBatchDedicatedResources(params)
	if err != nil {
		return nil, err
	}

	job := &cloudpb.BatchPredictionJob{
		DisplayName:     firstNonEmpty(stringParam(params, "display_name"), defaultDisplayName("vertex-batch")),
		Model:           modelResource(s.projectID, s.location, model),
		InputConfig:     inputConfig,
		OutputConfig:    outputConfig,
		ModelParameters: modelParameters,
		Labels:          labels,
	}
	if dedicatedResources != nil {
		job.DedicatedResources = dedicatedResources
	}
	if serviceAccount := stringParam(params, "service_account"); serviceAccount != "" {
		job.ServiceAccount = serviceAccount
	}
	if generateExplanation, err := boolParam(params, "generate_explanation", false); err != nil {
		return nil, err
	} else {
		job.GenerateExplanation = generateExplanation
	}

	return &cloudpb.CreateBatchPredictionJobRequest{
		Parent:             locationParent(s.projectID, s.location),
		BatchPredictionJob: job,
	}, nil
}

func buildBatchInputConfig(inputURI, instancesFormat string) (*cloudpb.BatchPredictionJob_InputConfig, error) {
	switch {
	case strings.HasPrefix(inputURI, "gs://"):
		return &cloudpb.BatchPredictionJob_InputConfig{
			Source: &cloudpb.BatchPredictionJob_InputConfig_GcsSource{
				GcsSource: &cloudpb.GcsSource{Uris: []string{inputURI}},
			},
			InstancesFormat: instancesFormat,
		}, nil
	case strings.HasPrefix(inputURI, "bq://"):
		return &cloudpb.BatchPredictionJob_InputConfig{
			Source: &cloudpb.BatchPredictionJob_InputConfig_BigquerySource{
				BigquerySource: &cloudpb.BigQuerySource{InputUri: inputURI},
			},
			InstancesFormat: firstNonEmpty(instancesFormat, "bigquery"),
		}, nil
	default:
		return nil, fmt.Errorf("input_uri must be a gs:// or bq:// URI")
	}
}

func buildBatchOutputConfig(outputURI, predictionsFormat string) (*cloudpb.BatchPredictionJob_OutputConfig, error) {
	switch {
	case strings.HasPrefix(outputURI, "gs://"):
		return &cloudpb.BatchPredictionJob_OutputConfig{
			Destination: &cloudpb.BatchPredictionJob_OutputConfig_GcsDestination{
				GcsDestination: &cloudpb.GcsDestination{OutputUriPrefix: outputURI},
			},
			PredictionsFormat: predictionsFormat,
		}, nil
	case strings.HasPrefix(outputURI, "bq://"):
		return &cloudpb.BatchPredictionJob_OutputConfig{
			Destination: &cloudpb.BatchPredictionJob_OutputConfig_BigqueryDestination{
				BigqueryDestination: &cloudpb.BigQueryDestination{OutputUri: outputURI},
			},
			PredictionsFormat: firstNonEmpty(predictionsFormat, "bigquery"),
		}, nil
	default:
		return nil, fmt.Errorf("output_uri must be a gs:// or bq:// URI")
	}
}

func buildBatchDedicatedResources(params map[string]any) (*cloudpb.BatchDedicatedResources, error) {
	machineType := stringParam(params, "machine_type")
	startingReplicaCount, err := intParam(params, "starting_replica_count", 0)
	if err != nil {
		return nil, err
	}
	maxReplicaCount, err := intParam(params, "max_replica_count", 0)
	if err != nil {
		return nil, err
	}

	if machineType == "" && startingReplicaCount == 0 && maxReplicaCount == 0 {
		return nil, nil
	}
	if machineType == "" {
		return nil, fmt.Errorf("machine_type is required when dedicated resources are configured")
	}
	if startingReplicaCount <= 0 {
		startingReplicaCount = 1
	}
	if maxReplicaCount <= 0 {
		maxReplicaCount = startingReplicaCount
	}
	if maxReplicaCount < startingReplicaCount {
		return nil, fmt.Errorf("max_replica_count must be greater than or equal to starting_replica_count")
	}

	return &cloudpb.BatchDedicatedResources{
		MachineSpec: &cloudpb.MachineSpec{
			MachineType: machineType,
		},
		StartingReplicaCount: int32(startingReplicaCount),
		MaxReplicaCount:      int32(maxReplicaCount),
	}, nil
}

func inferBatchFormat(uri, fallback string) string {
	if strings.HasPrefix(uri, "bq://") {
		return "bigquery"
	}
	return fallback
}
