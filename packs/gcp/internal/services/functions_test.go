package services

import (
	"context"
	"testing"
)

func TestFunctionsCallValidation(t *testing.T) {
	t.Parallel()

	svc := &FunctionsService{}
	_, err := svc.CallFunction(context.Background(), map[string]any{})
	assertErrMsg(t, err, "function_name is required")
}

func TestFunctionsGetValidation(t *testing.T) {
	t.Parallel()

	svc := &FunctionsService{}
	_, err := svc.GetFunction(context.Background(), map[string]any{})
	assertErrMsg(t, err, "function_name is required")
}

func TestFunctionsFunctionParentUsesWildcardForGlobal(t *testing.T) {
	t.Parallel()

	svc := &FunctionsService{projectID: "demo-project", location: "global"}
	if got, want := svc.functionParent(), "projects/demo-project/locations/-"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFunctionsFunctionResource(t *testing.T) {
	t.Parallel()

	t.Run("uses_full_resource_as_is", func(t *testing.T) {
		svc := &FunctionsService{projectID: "demo-project", location: "us-central1"}
		full := "projects/other/locations/us-central1/functions/test-fn"
		got, err := svc.functionResource(full)
		if err != nil {
			t.Fatalf("functionResource returned error: %v", err)
		}
		if got != full {
			t.Fatalf("expected %q, got %q", full, got)
		}
	})

	t.Run("builds_resource_for_short_name", func(t *testing.T) {
		svc := &FunctionsService{projectID: "demo-project", location: "us-central1"}
		got, err := svc.functionResource("test-fn")
		if err != nil {
			t.Fatalf("functionResource returned error: %v", err)
		}
		want := "projects/demo-project/locations/us-central1/functions/test-fn"
		if got != want {
			t.Fatalf("expected %q, got %q", want, got)
		}
	})

	t.Run("requires_location_for_short_name", func(t *testing.T) {
		svc := &FunctionsService{projectID: "demo-project", location: "global"}
		_, err := svc.functionResource("test-fn")
		assertErrMsg(t, err, "location is required when function_name is not fully qualified")
	})
}
