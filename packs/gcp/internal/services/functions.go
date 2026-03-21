package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	functions "cloud.google.com/go/functions/apiv1"
	functionspb "cloud.google.com/go/functions/apiv1/functionspb"
	giterator "google.golang.org/api/iterator"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

// FunctionsService wraps Google Cloud Functions operations.
type FunctionsService struct {
	client    *functions.CloudFunctionsClient
	projectID string
	location  string
}

// NewFunctionsService creates a Functions service for the given request config.
func NewFunctionsService(ctx context.Context, reqCfg gcpclient.RequestConfig) (*FunctionsService, error) {
	client, err := functions.NewCloudFunctionsClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create functions client: %w", err)
	}
	return &FunctionsService{
		client:    client,
		projectID: reqCfg.ProjectID,
		location:  reqCfg.Location,
	}, nil
}

// Close releases any client resources.
func (s *FunctionsService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// CallFunction invokes a Cloud Function.
func (s *FunctionsService) CallFunction(ctx context.Context, params map[string]any) (any, error) {
	functionName := stringParam(params, "function_name")
	if functionName == "" {
		return nil, fmt.Errorf("function_name is required")
	}

	resourceName, err := s.functionResource(functionName)
	if err != nil {
		return nil, err
	}

	payload := ""
	if rawPayload, ok := params["payload"]; ok && rawPayload != nil {
		switch typed := rawPayload.(type) {
		case string:
			payload = typed
		default:
			data, err := json.Marshal(typed)
			if err != nil {
				return nil, fmt.Errorf("marshal payload: %w", err)
			}
			payload = string(data)
		}
	}

	response, err := s.client.CallFunction(ctx, &functionspb.CallFunctionRequest{
		Name: resourceName,
		Data: payload,
	})
	if err != nil {
		return nil, err
	}

	return protoToAny(response)
}

// GetFunction returns a Cloud Function definition.
func (s *FunctionsService) GetFunction(ctx context.Context, params map[string]any) (any, error) {
	functionName := stringParam(params, "function_name")
	if functionName == "" {
		return nil, fmt.Errorf("function_name is required")
	}

	resourceName, err := s.functionResource(functionName)
	if err != nil {
		return nil, err
	}

	versionID, err := intParam(params, "version_id", 0)
	if err != nil {
		return nil, err
	}

	response, err := s.client.GetFunction(ctx, &functionspb.GetFunctionRequest{
		Name:      resourceName,
		VersionId: int64(versionID),
	})
	if err != nil {
		return nil, err
	}

	return protoToAny(response)
}

// ListFunctions lists functions in the resolved project/location.
func (s *FunctionsService) ListFunctions(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}

	pageToken := stringParam(params, "page_token")
	it := s.client.ListFunctions(ctx, &functionspb.ListFunctionsRequest{
		Parent:    s.functionParent(),
		PageSize:  pageSize,
		PageToken: pageToken,
	})

	pager := giterator.NewPager(it, int(pageSize), pageToken)
	var functions []*functionspb.CloudFunction
	nextPageToken, err := pager.NextPage(&functions)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(functions)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"functions":       mapped,
		"next_page_token": nextPageToken,
	}, nil
}

func (s *FunctionsService) functionParent() string {
	location := strings.TrimSpace(s.location)
	if location == "" || strings.EqualFold(location, "global") {
		location = "-"
	}
	return fmt.Sprintf("projects/%s/locations/%s", s.projectID, location)
}

func (s *FunctionsService) functionResource(functionName string) (string, error) {
	if isFullResource(functionName) {
		return functionName, nil
	}
	location := strings.TrimSpace(s.location)
	if location == "" || strings.EqualFold(location, "global") {
		return "", fmt.Errorf("location is required when function_name is not fully qualified")
	}
	return fmt.Sprintf("projects/%s/locations/%s/functions/%s", s.projectID, location, functionName), nil
}
