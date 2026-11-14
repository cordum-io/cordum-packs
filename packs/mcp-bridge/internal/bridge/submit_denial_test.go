package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSubmitTimeDenialPreservesMCPJobEnvelope(t *testing.T) {
	var submits, lookups, executions atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs":
			submits.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":"unsafe cancellation","status":403,"job_id":"job-denied","trace_id":"trace-fixture"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job-denied":
			lookups.Add(1)
			_, _ = fmt.Fprint(w, `{"id":"job-denied","state":"DENIED","safety_reason":"unsafe cancellation"}`)
		default:
			executions.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer gateway.Close()
	b := &Bridge{client: newGatewayClient(gateway.URL, "fixture-key", "default")}
	b.tools = b.buildTools()
	result, err := b.CallTool(context.Background(), "cordum.workflow.cancel", map[string]any{"workflow_id": "safe-fixture", "run_id": "run-fixture"})
	if err != nil || !result.IsError || len(result.Content) != 1 {
		t.Fatalf("expected MCP tool-error envelope, result=%+v error=%v", result, err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(result.Content[0].Text), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["job_id"] != "job-denied" || payload["state"] != "DENIED" || payload["reason"] != "unsafe cancellation" {
		t.Fatalf("submit-time policy denial lost its stored job: %+v", payload)
	}
	if submits.Load() != 1 || lookups.Load() != 1 || executions.Load() != 0 {
		t.Fatalf("requests submit=%d lookup=%d execution=%d", submits.Load(), lookups.Load(), executions.Load())
	}
}

func TestSubmitTime403DoesNotInventPolicyDenial(t *testing.T) {
	for _, tc := range []struct {
		name, body, detail string
		lookupStatus       int
		wantLookups        int32
		submitStatus       int
	}{
		{"auth failure", `{"error":"tenant access denied"}`, "", http.StatusOK, 0, http.StatusForbidden},
		{"unavailable job", `{"error":"forbidden","job_id":"job-1"}`, "", http.StatusNotFound, 1, http.StatusForbidden},
		{"approval is not denial", `{"error":"forbidden","job_id":"job-1"}`, `{"id":"job-1","state":"APPROVAL_REQUIRED"}`, http.StatusOK, 1, http.StatusForbidden},
		{"success is not denial", `{"error":"forbidden","job_id":"job-1"}`, `{"id":"job-1","state":"SUCCEEDED"}`, http.StatusOK, 1, http.StatusForbidden},
		{"different job", `{"error":"forbidden","job_id":"job-1"}`, `{"id":"job-other","state":"DENIED"}`, http.StatusOK, 1, http.StatusForbidden},
		{"malformed forbidden", `not-json`, "", http.StatusOK, 0, http.StatusForbidden},
		{"server failure", `{"error":"unavailable","job_id":"job-1"}`, `{"id":"job-1","state":"DENIED"}`, http.StatusOK, 0, http.StatusServiceUnavailable},
		{"invalid request", `{"error":"invalid","job_id":"job-1"}`, `{"id":"job-1","state":"DENIED"}`, http.StatusOK, 0, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lookups atomic.Int32
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					w.WriteHeader(tc.submitStatus)
					_, _ = fmt.Fprint(w, tc.body)
					return
				}
				lookups.Add(1)
				w.WriteHeader(tc.lookupStatus)
				_, _ = fmt.Fprint(w, tc.detail)
			}))
			defer gateway.Close()
			b := &Bridge{client: newGatewayClient(gateway.URL, "fixture-key", "default")}
			result, err := b.submitToolJob(context.Background(), "cordum.workflow.cancel", nil)
			if result != nil || err == nil || err.Error() != "gateway error: "+tc.body {
				t.Fatalf("original gateway failure was not preserved: result=%v error=%v", result, err)
			}
			if lookups.Load() != tc.wantLookups {
				t.Fatalf("lookup count=%d, want %d", lookups.Load(), tc.wantLookups)
			}
		})
	}
}
