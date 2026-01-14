package worker

import (
	"net/http"
	"testing"
)

func TestSplitParamsGET(t *testing.T) {
	params := map[string]any{
		"sys_id":        "abc",
		"sysparm_query": "state=1",
		"fields":        []string{"number", "state"},
	}
	spec := actionSpec{Method: http.MethodGet, PathParam: "sys_id"}
	query, body, err := splitParams(params, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != nil {
		t.Fatalf("expected nil body for GET")
	}
	if got := query.Get("sysparm_query"); got != "state=1" {
		t.Fatalf("unexpected sysparm_query: %q", got)
	}
	if got := query.Get("fields"); got != "number,state" {
		t.Fatalf("unexpected fields: %q", got)
	}
}

func TestSplitParamsBody(t *testing.T) {
	params := map[string]any{
		"sys_id": "abc",
		"state":  "2",
	}
	spec := actionSpec{Method: http.MethodPatch, PathParam: "sys_id", Body: true}
	_, body, err := splitParams(params, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body == nil || body["state"] != "2" {
		t.Fatalf("expected state in body")
	}
	if _, ok := body["sys_id"]; ok {
		t.Fatalf("expected sys_id excluded from body")
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"sys_id": "abc"}
	if err := validateParams(params, []string{"sys_id"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(params, []string{"missing"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}
