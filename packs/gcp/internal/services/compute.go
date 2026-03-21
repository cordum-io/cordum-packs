package services

import (
	"context"
	"fmt"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	giterator "google.golang.org/api/iterator"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

// ComputeService wraps Compute Engine instance operations.
type ComputeService struct {
	client    *compute.InstancesClient
	projectID string
	location  string
}

// NewComputeService creates a Compute service.
func NewComputeService(ctx context.Context, reqCfg gcpclient.RequestConfig) (*ComputeService, error) {
	client, err := compute.NewInstancesRESTClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create compute client: %w", err)
	}
	return &ComputeService{
		client:    client,
		projectID: reqCfg.ProjectID,
		location:  reqCfg.Location,
	}, nil
}

// Close releases any client resources.
func (s *ComputeService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// ListInstances lists instances in a specific zone.
func (s *ComputeService) ListInstances(ctx context.Context, params map[string]any) (any, error) {
	zone := s.zoneFromParams(params)
	if zone == "" {
		return nil, fmt.Errorf("zone is required")
	}

	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")

	request := &computepb.ListInstancesRequest{
		Project:    s.projectID,
		Zone:       zone,
		PageToken:  ptr(pageToken),
		MaxResults: ptr(uint32(pageSize)),
	}
	if filter := stringParam(params, "filter"); filter != "" {
		request.Filter = ptr(filter)
	}
	if orderBy := stringParam(params, "order_by"); orderBy != "" {
		request.OrderBy = ptr(orderBy)
	}
	if partial, err := boolParam(params, "return_partial_success", false); err == nil && partial {
		request.ReturnPartialSuccess = ptr(partial)
	} else if err != nil {
		return nil, err
	}

	it := s.client.List(ctx, request)
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var instances []*computepb.Instance
	nextPageToken, err := pager.NextPage(&instances)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(instances)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"instances":       mapped,
		"next_page_token": nextPageToken,
	}, nil
}

// GetInstance returns a single instance.
func (s *ComputeService) GetInstance(ctx context.Context, params map[string]any) (any, error) {
	instance := stringParam(params, "instance")
	if instance == "" {
		instance = stringParam(params, "instance_name")
	}
	if instance == "" {
		return nil, fmt.Errorf("instance or instance_name is required")
	}

	zone := s.zoneFromParams(params)
	if zone == "" {
		return nil, fmt.Errorf("zone is required")
	}

	response, err := s.client.Get(ctx, &computepb.GetInstanceRequest{
		Project:  s.projectID,
		Zone:     zone,
		Instance: instance,
	})
	if err != nil {
		return nil, err
	}

	return protoToAny(response)
}

// AggregatedListInstances lists instances across all visible scopes.
func (s *ComputeService) AggregatedListInstances(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")

	request := &computepb.AggregatedListInstancesRequest{
		Project:    s.projectID,
		PageToken:  ptr(pageToken),
		MaxResults: ptr(uint32(pageSize)),
	}
	if filter := stringParam(params, "filter"); filter != "" {
		request.Filter = ptr(filter)
	}
	if orderBy := stringParam(params, "order_by"); orderBy != "" {
		request.OrderBy = ptr(orderBy)
	}
	if includeAllScopes, err := boolParam(params, "include_all_scopes", false); err == nil && includeAllScopes {
		request.IncludeAllScopes = ptr(includeAllScopes)
	} else if err != nil {
		return nil, err
	}
	if partial, err := boolParam(params, "return_partial_success", false); err == nil && partial {
		request.ReturnPartialSuccess = ptr(partial)
	} else if err != nil {
		return nil, err
	}

	it := s.client.AggregatedList(ctx, request)
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var pairs []compute.InstancesScopedListPair
	nextPageToken, err := pager.NextPage(&pairs)
	if err != nil {
		return nil, err
	}

	results := make([]map[string]any, 0, len(pairs))
	for _, pair := range pairs {
		value, err := protoToAny(pair.Value)
		if err != nil {
			return nil, err
		}
		results = append(results, map[string]any{
			"scope": pair.Key,
			"value": value,
		})
	}

	return map[string]any{
		"scopes":          results,
		"next_page_token": nextPageToken,
	}, nil
}

func (s *ComputeService) zoneFromParams(params map[string]any) string {
	zone := stringParam(params, "zone")
	if zone != "" {
		return zone
	}
	if location := strings.TrimSpace(s.location); location != "" && !strings.EqualFold(location, "global") {
		return location
	}
	return ""
}
