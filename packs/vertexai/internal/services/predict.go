package services

import (
	"context"
	"encoding/json"
	"fmt"

	aiplatform "cloud.google.com/go/aiplatform/apiv1"
	cloudpb "cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
	httpbodypb "google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/vertexclient"
)

// PredictService wraps Vertex AI online prediction operations.
type PredictService struct {
	client    *aiplatform.PredictionClient
	projectID string
	location  string
}

// NewPredictService creates a prediction service.
func NewPredictService(ctx context.Context, reqCfg vertexclient.RequestConfig) (*PredictService, error) {
	client, err := aiplatform.NewPredictionClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create prediction client: %w", err)
	}
	return &PredictService{
		client:    client,
		projectID: reqCfg.ProjectID,
		location:  reqCfg.Location,
	}, nil
}

// Close releases client resources.
func (s *PredictService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// Predict performs online prediction.
func (s *PredictService) Predict(ctx context.Context, params map[string]any) (any, error) {
	request, err := s.buildPredictRequest(params)
	if err != nil {
		return nil, err
	}

	response, err := s.client.Predict(ctx, request)
	if err != nil {
		return nil, err
	}
	return protoToAny(response)
}

// RawPredict performs raw prediction and returns the response body.
func (s *PredictService) RawPredict(ctx context.Context, params map[string]any) (any, error) {
	request, err := s.buildRawPredictRequest(params)
	if err != nil {
		return nil, err
	}

	response, err := s.client.RawPredict(ctx, request)
	if err != nil {
		return nil, err
	}
	return httpBodyResult(response.GetContentType(), response.GetData()), nil
}

func (s *PredictService) buildPredictRequest(params map[string]any) (*cloudpb.PredictRequest, error) {
	endpointID := stringParam(params, "endpoint_id")
	if endpointID == "" {
		return nil, fmt.Errorf("endpoint_id is required")
	}

	rawInstances, ok := params["instances"]
	if !ok || rawInstances == nil {
		return nil, fmt.Errorf("instances are required")
	}
	rawList, ok := rawInstances.([]any)
	if !ok || len(rawList) == 0 {
		return nil, fmt.Errorf("instances must be a non-empty array")
	}

	instances := make([]*structpb.Value, 0, len(rawList))
	for _, instance := range rawList {
		value, err := structValueFromAny(instance)
		if err != nil {
			return nil, fmt.Errorf("invalid instance: %w", err)
		}
		instances = append(instances, value)
	}

	parameters, err := structValueFromAny(params["parameters"])
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	return &cloudpb.PredictRequest{
		Endpoint:   endpointResource(s.projectID, s.location, endpointID),
		Instances:  instances,
		Parameters: parameters,
	}, nil
}

func (s *PredictService) buildRawPredictRequest(params map[string]any) (*cloudpb.RawPredictRequest, error) {
	endpointID := stringParam(params, "endpoint_id")
	if endpointID == "" {
		return nil, fmt.Errorf("endpoint_id is required")
	}

	contentType := stringParam(params, "content_type")
	if contentType == "" {
		contentType = "application/json"
	}

	body := stringParam(params, "body")
	if body == "" {
		payload := map[string]any{}
		if instances, ok := params["instances"]; ok {
			payload["instances"] = instances
		}
		if parameters, ok := params["parameters"]; ok && parameters != nil {
			payload["parameters"] = parameters
		}
		if len(payload) == 0 {
			return nil, fmt.Errorf("body or instances is required")
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal raw predict body: %w", err)
		}
		body = string(data)
	}

	return &cloudpb.RawPredictRequest{
		Endpoint: endpointResource(s.projectID, s.location, endpointID),
		HttpBody: &httpbodypb.HttpBody{
			ContentType: contentType,
			Data:        []byte(body),
		},
	}, nil
}
