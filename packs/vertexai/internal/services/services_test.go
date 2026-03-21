package services

import (
	"strings"
	"testing"
)

func assertErrMsg(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %q, got nil", want)
	}
	if err.Error() != want {
		t.Fatalf("expected error %q, got %q", want, err.Error())
	}
}

func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got %q", want, err.Error())
	}
}

func TestPageSizeParamClampsRange(t *testing.T) {
	t.Parallel()

	got, err := pageSizeParam(map[string]any{"page_size": maxListPageSize + 50})
	if err != nil {
		t.Fatalf("pageSizeParam returned error: %v", err)
	}
	if got != maxListPageSize {
		t.Fatalf("expected clamped page size %d, got %d", maxListPageSize, got)
	}
}

func TestBuildBatchDedicatedResourcesValidation(t *testing.T) {
	t.Parallel()

	_, err := buildBatchDedicatedResources(map[string]any{
		"starting_replica_count": 2,
	})
	assertErrMsg(t, err, "machine_type is required when dedicated resources are configured")
}

func TestBuildBatchInputConfigSupportsBigQuery(t *testing.T) {
	t.Parallel()

	cfg, err := buildBatchInputConfig("bq://demo.dataset.table", "")
	if err != nil {
		t.Fatalf("buildBatchInputConfig returned error: %v", err)
	}
	if cfg.GetBigquerySource().GetInputUri() != "bq://demo.dataset.table" {
		t.Fatalf("unexpected bigquery source: %+v", cfg.GetBigquerySource())
	}
	if cfg.GetInstancesFormat() != "bigquery" {
		t.Fatalf("expected bigquery format, got %q", cfg.GetInstancesFormat())
	}
}

func TestTrainingBuildRequestValidation(t *testing.T) {
	t.Parallel()

	svc := &TrainingService{projectID: "demo-project", location: "us-central1"}
	_, err := svc.buildCreateTrainingPipelineRequest(map[string]any{})
	assertErrMsg(t, err, "training_task_definition is required")
}

func TestTrainingBuildRequestIncludesModelToUpload(t *testing.T) {
	t.Parallel()

	svc := &TrainingService{projectID: "demo-project", location: "us-central1"}
	req, err := svc.buildCreateTrainingPipelineRequest(map[string]any{
		"training_task_definition": "gs://definitions/custom_training.yaml",
		"training_task_inputs":     map[string]any{"workerPoolSpecs": []any{}},
		"model_to_upload": map[string]any{
			"display_name": "demo-model",
			"description":  "test model",
		},
	})
	if err != nil {
		t.Fatalf("buildCreateTrainingPipelineRequest returned error: %v", err)
	}
	if req.GetTrainingPipeline().GetModelToUpload().GetDisplayName() != "demo-model" {
		t.Fatalf("unexpected model_to_upload: %+v", req.GetTrainingPipeline().GetModelToUpload())
	}
}

func TestReadMaskParamSupportsCommaSeparatedString(t *testing.T) {
	t.Parallel()

	mask, err := readMaskParam(map[string]any{"read_mask": "name,state"}, "read_mask")
	if err != nil {
		t.Fatalf("readMaskParam returned error: %v", err)
	}
	if len(mask.GetPaths()) != 2 || mask.GetPaths()[0] != "name" || mask.GetPaths()[1] != "state" {
		t.Fatalf("unexpected mask paths: %+v", mask.GetPaths())
	}
}
