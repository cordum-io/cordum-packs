package services

import (
	"testing"
)

func TestPredictBuildRequestValidation(t *testing.T) {
	t.Parallel()

	svc := &PredictService{projectID: "demo-project", location: "us-central1"}

	_, err := svc.buildPredictRequest(map[string]any{})
	assertErrMsg(t, err, "endpoint_id is required")

	_, err = svc.buildPredictRequest(map[string]any{
		"endpoint_id": "123",
	})
	assertErrMsg(t, err, "instances are required")
}

func TestPredictBuildRequest(t *testing.T) {
	t.Parallel()

	svc := &PredictService{projectID: "demo-project", location: "us-central1"}
	req, err := svc.buildPredictRequest(map[string]any{
		"endpoint_id": "123",
		"instances": []any{
			map[string]any{"text": "hello"},
		},
		"parameters": map[string]any{"temperature": 0.2},
	})
	if err != nil {
		t.Fatalf("buildPredictRequest returned error: %v", err)
	}
	if req.GetEndpoint() != "projects/demo-project/locations/us-central1/endpoints/123" {
		t.Fatalf("unexpected endpoint: %q", req.GetEndpoint())
	}
	if len(req.GetInstances()) != 1 {
		t.Fatalf("expected one instance, got %d", len(req.GetInstances()))
	}
}

func TestRawPredictBuildRequestValidation(t *testing.T) {
	t.Parallel()

	svc := &PredictService{projectID: "demo-project", location: "us-central1"}
	_, err := svc.buildRawPredictRequest(map[string]any{
		"endpoint_id": "123",
	})
	assertErrMsg(t, err, "body or instances is required")
}

func TestRawPredictBuildRequestUsesJSONFallback(t *testing.T) {
	t.Parallel()

	svc := &PredictService{projectID: "demo-project", location: "us-central1"}
	req, err := svc.buildRawPredictRequest(map[string]any{
		"endpoint_id": "123",
		"instances": []any{
			map[string]any{"text": "hello"},
		},
	})
	if err != nil {
		t.Fatalf("buildRawPredictRequest returned error: %v", err)
	}
	if req.GetHttpBody().GetContentType() != "application/json" {
		t.Fatalf("unexpected content type: %q", req.GetHttpBody().GetContentType())
	}
	if len(req.GetHttpBody().GetData()) == 0 {
		t.Fatal("expected marshaled request body")
	}
}
