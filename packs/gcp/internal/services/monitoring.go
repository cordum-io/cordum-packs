package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	monitoringpb "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	giterator "google.golang.org/api/iterator"
	metricpb "google.golang.org/genproto/googleapis/api/metric"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

// MonitoringService wraps Cloud Monitoring operations.
type MonitoringService struct {
	metrics   *monitoring.MetricClient
	alerts    *monitoring.AlertPolicyClient
	projectID string
}

// NewMonitoringService creates a Monitoring service.
func NewMonitoringService(ctx context.Context, reqCfg gcpclient.RequestConfig) (*MonitoringService, error) {
	metrics, err := monitoring.NewMetricClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create monitoring metric client: %w", err)
	}
	alerts, err := monitoring.NewAlertPolicyClient(ctx, reqCfg.Options...)
	if err != nil {
		_ = metrics.Close()
		return nil, fmt.Errorf("create monitoring alert client: %w", err)
	}
	return &MonitoringService{
		metrics:   metrics,
		alerts:    alerts,
		projectID: reqCfg.ProjectID,
	}, nil
}

// Close releases any client resources.
func (s *MonitoringService) Close() error {
	if s.metrics != nil {
		_ = s.metrics.Close()
	}
	if s.alerts != nil {
		return s.alerts.Close()
	}
	return nil
}

// ListTimeSeries lists time series for a monitoring filter.
func (s *MonitoringService) ListTimeSeries(ctx context.Context, params map[string]any) (any, error) {
	filter := stringParam(params, "filter")
	if filter == "" {
		return nil, fmt.Errorf("filter is required")
	}

	intervalStart, intervalEnd, err := s.timeIntervalFromParams(params)
	if err != nil {
		return nil, err
	}

	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")

	it := s.metrics.ListTimeSeries(ctx, &monitoringpb.ListTimeSeriesRequest{
		Name:   s.projectResource(),
		Filter: filter,
		Interval: &monitoringpb.TimeInterval{
			StartTime: timestamppb.New(intervalStart),
			EndTime:   timestamppb.New(intervalEnd),
		},
		View:      s.timeSeriesView(params),
		PageSize:  pageSize,
		PageToken: pageToken,
	})
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var series []*monitoringpb.TimeSeries
	nextPageToken, err := pager.NextPage(&series)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(series)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"time_series":     mapped,
		"next_page_token": nextPageToken,
	}, nil
}

// ListMetricDescriptors lists metric descriptors for the project.
func (s *MonitoringService) ListMetricDescriptors(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")

	it := s.metrics.ListMetricDescriptors(ctx, &monitoringpb.ListMetricDescriptorsRequest{
		Name:      s.projectResource(),
		Filter:    stringParam(params, "filter"),
		PageSize:  pageSize,
		PageToken: pageToken,
	})
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var descriptors []*metricpb.MetricDescriptor
	nextPageToken, err := pager.NextPage(&descriptors)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(descriptors)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"metric_descriptors": mapped,
		"next_page_token":    nextPageToken,
	}, nil
}

// ListAlertPolicies lists alert policies for the project.
func (s *MonitoringService) ListAlertPolicies(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")

	it := s.alerts.ListAlertPolicies(ctx, &monitoringpb.ListAlertPoliciesRequest{
		Name:      s.projectResource(),
		Filter:    stringParam(params, "filter"),
		OrderBy:   stringParam(params, "order_by"),
		PageSize:  pageSize,
		PageToken: pageToken,
	})
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var policies []*monitoringpb.AlertPolicy
	nextPageToken, err := pager.NextPage(&policies)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(policies)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"alert_policies":  mapped,
		"next_page_token": nextPageToken,
	}, nil
}

func (s *MonitoringService) projectResource() string {
	return fmt.Sprintf("projects/%s", s.projectID)
}

func (s *MonitoringService) timeIntervalFromParams(params map[string]any) (time.Time, time.Time, error) {
	endTime, ok, err := timeParam(params, "interval_end")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !ok {
		endTime = time.Now().UTC()
	}

	startTime, ok, err := timeParam(params, "interval_start")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !ok {
		startTime = endTime.Add(-1 * time.Hour)
	}

	if !startTime.Before(endTime) {
		return time.Time{}, time.Time{}, fmt.Errorf("interval_start must be before interval_end")
	}

	return startTime, endTime, nil
}

func (s *MonitoringService) timeSeriesView(params map[string]any) monitoringpb.ListTimeSeriesRequest_TimeSeriesView {
	switch strings.ToUpper(stringParam(params, "view")) {
	case "HEADERS":
		return monitoringpb.ListTimeSeriesRequest_HEADERS
	default:
		return monitoringpb.ListTimeSeriesRequest_FULL
	}
}
