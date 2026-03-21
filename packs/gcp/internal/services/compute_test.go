package services

import (
	"context"
	"testing"
)

func TestComputeListInstancesValidation(t *testing.T) {
	t.Parallel()

	svc := &ComputeService{}
	_, err := svc.ListInstances(context.Background(), map[string]any{})
	assertErrMsg(t, err, "zone is required")
}

func TestComputeGetInstanceValidation(t *testing.T) {
	t.Parallel()

	svc := &ComputeService{}
	_, err := svc.GetInstance(context.Background(), map[string]any{})
	assertErrMsg(t, err, "instance or instance_name is required")
}

func TestComputeAggregatedListRejectsInvalidBoolean(t *testing.T) {
	t.Parallel()

	svc := &ComputeService{projectID: "demo-project"}
	_, err := svc.AggregatedListInstances(context.Background(), map[string]any{
		"include_all_scopes": "sometimes",
	})
	assertErrContains(t, err, "include_all_scopes must be boolean")
}

func TestComputeZoneFromParams(t *testing.T) {
	t.Parallel()

	if got := (&ComputeService{location: "us-central1-a"}).zoneFromParams(nil); got != "us-central1-a" {
		t.Fatalf("expected fallback zone %q, got %q", "us-central1-a", got)
	}
	if got := (&ComputeService{location: "global"}).zoneFromParams(nil); got != "" {
		t.Fatalf("expected empty zone for global location, got %q", got)
	}
	if got := (&ComputeService{location: "us-central1-a"}).zoneFromParams(map[string]any{"zone": "europe-west1-b"}); got != "europe-west1-b" {
		t.Fatalf("expected explicit zone override, got %q", got)
	}
}
