package worker

import "testing"

func TestNormalizePayload(t *testing.T) {
	if normalizePayload(nil) == nil {
		t.Fatal("expected non-nil")
	}
	r := normalizePayload(map[string]any{"context": map[string]any{"action": "query"}})
	if r["action"] != "query" {
		t.Errorf("expected query, got %v", r["action"])
	}
}

func TestDecodePayload(t *testing.T) {
	var input JobInput
	if err := decodePayload(map[string]any{"action": "ingest", "profile": "default"}, &input); err != nil {
		t.Fatal(err)
	}
	if input.Action != "ingest" {
		t.Errorf("expected ingest, got %q", input.Action)
	}
}

func TestJobResultFields(t *testing.T) {
	result := JobResult{
		JobID:             "job-1",
		Action:            "query",
		Response:          "The answer is 42.",
		DocumentsIngested: 0,
	}
	if result.Response != "The answer is 42." {
		t.Errorf("unexpected response: %q", result.Response)
	}
}
