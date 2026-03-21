package services

import (
	"context"
	"testing"
	"time"

	monitoringpb "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
)

func TestMonitoringListTimeSeriesValidation(t *testing.T) {
	t.Parallel()

	svc := &MonitoringService{}
	_, err := svc.ListTimeSeries(context.Background(), map[string]any{})
	assertErrMsg(t, err, "filter is required")
}

func TestMonitoringListMetricDescriptorsValidation(t *testing.T) {
	t.Parallel()

	svc := &MonitoringService{}
	_, err := svc.ListMetricDescriptors(context.Background(), map[string]any{"page_size": "oops"})
	assertErrContains(t, err, "page_size must be an integer")
}

func TestMonitoringListAlertPoliciesValidation(t *testing.T) {
	t.Parallel()

	svc := &MonitoringService{}
	_, err := svc.ListAlertPolicies(context.Background(), map[string]any{"page_size": "oops"})
	assertErrContains(t, err, "page_size must be an integer")
}

func TestMonitoringTimeIntervalFromParams(t *testing.T) {
	t.Parallel()

	svc := &MonitoringService{}

	t.Run("defaults_to_last_hour", func(t *testing.T) {
		start, end, err := svc.timeIntervalFromParams(nil)
		if err != nil {
			t.Fatalf("timeIntervalFromParams returned error: %v", err)
		}
		if diff := end.Sub(start); diff != time.Hour {
			t.Fatalf("expected one hour interval, got %v", diff)
		}
	})

	t.Run("rejects_inverted_interval", func(t *testing.T) {
		_, _, err := svc.timeIntervalFromParams(map[string]any{
			"interval_start": "2026-03-21T10:00:00Z",
			"interval_end":   "2026-03-21T09:00:00Z",
		})
		assertErrMsg(t, err, "interval_start must be before interval_end")
	})
}

func TestMonitoringHelpers(t *testing.T) {
	t.Parallel()

	svc := &MonitoringService{projectID: "demo-project"}
	if got, want := svc.projectResource(), "projects/demo-project"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got := svc.timeSeriesView(map[string]any{"view": "HEADERS"}); got != monitoringpb.ListTimeSeriesRequest_HEADERS {
		t.Fatalf("expected HEADERS view, got %v", got)
	}
	if got := svc.timeSeriesView(map[string]any{"view": "full"}); got != monitoringpb.ListTimeSeriesRequest_FULL {
		t.Fatalf("expected FULL view, got %v", got)
	}
}
