package worker

import (
	"net/http"
	"reflect"
	"testing"
)

func TestSplitParamsHeaders(t *testing.T) {
	params := map[string]any{
		"id":          "P123",
		"from":        "user@example.com",
		"statuses[]":  []string{"triggered", "acknowledged"},
		"urgencies[]": []string{"high"},
	}
	spec := actionSpec{Method: http.MethodGet, PathParam: "id", HeaderParams: map[string]string{"from": "From"}}
	query, body, headers, err := splitParams(params, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != nil {
		t.Fatalf("expected nil body for GET")
	}
	if headers["From"] != "user@example.com" {
		t.Fatalf("expected From header")
	}
	if got := query["statuses[]"]; !reflect.DeepEqual(got, []string{"triggered", "acknowledged"}) {
		t.Fatalf("unexpected statuses query: %v", got)
	}
}

func TestBuildIncidentBody(t *testing.T) {
	params := map[string]any{"incident": map[string]any{"priority": "high"}}
	body := buildIncidentBody("acknowledged", params)
	incident, ok := body["incident"].(map[string]any)
	if !ok {
		t.Fatalf("expected incident map")
	}
	if incident["status"] != "acknowledged" {
		t.Fatalf("expected status")
	}
	if incident["priority"] != "high" {
		t.Fatalf("expected priority merged")
	}

	override := map[string]any{"body": map[string]any{"custom": true}}
	body = buildIncidentBody("resolved", override)
	if body["custom"] != true {
		t.Fatalf("expected override body")
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"id": "P123", "from": "user@example.com"}
	if err := validateParams(params, []string{"id", "from"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(params, []string{"missing"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}
