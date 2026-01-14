package worker

import (
	"net/http"
	"testing"
)

func TestValidateParams(t *testing.T) {
	params := map[string]any{"id": "123", "query": "foo"}
	if err := validateParams(params, []string{"id", "query"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(params, []string{"missing"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
	params["id"] = "  "
	if err := validateParams(params, []string{"id"}); err == nil {
		t.Fatalf("expected error for empty string")
	}
}

func TestSplitParamsGET(t *testing.T) {
	params := map[string]any{
		"id":   "abc",
		"from": 1,
		"tags": []string{"env:prod", "service:api"},
	}
	spec := actionSpec{Method: http.MethodGet, PathParam: "id"}
	query, body, err := splitParams(params, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != nil {
		t.Fatalf("expected nil body for GET")
	}
	if got := query.Get("from"); got != "1" {
		t.Fatalf("expected from=1, got %q", got)
	}
	if got := query.Get("tags"); got != "env:prod,service:api" {
		t.Fatalf("expected tags joined, got %q", got)
	}
}

func TestSplitParamsPOST(t *testing.T) {
	params := map[string]any{
		"id":      "42",
		"scope":   "env:prod",
		"message": "investigating",
	}
	spec := actionSpec{Method: http.MethodPost, PathParam: "id", QueryKeys: []string{"scope"}, Body: true}
	query, body, err := splitParams(params, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := query.Get("scope"); got != "env:prod" {
		t.Fatalf("expected scope query, got %q", got)
	}
	if body == nil || body["message"] != "investigating" {
		t.Fatalf("expected message in body")
	}
	if _, ok := body["scope"]; ok {
		t.Fatalf("expected scope excluded from body")
	}
}
