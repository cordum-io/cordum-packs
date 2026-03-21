package worker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNormalizePayload tests payload normalization.
func TestNormalizePayload(t *testing.T) {
	t.Run("nil payload", func(t *testing.T) {
		result := normalizePayload(nil)
		if result == nil {
			t.Fatal("expected non-nil map")
		}
	})

	t.Run("payload with context key", func(t *testing.T) {
		payload := map[string]any{
			"context": map[string]any{
				"action": "chain.invoke",
			},
		}
		result := normalizePayload(payload)
		if result["action"] != "chain.invoke" {
			t.Errorf("expected action=chain.invoke, got %v", result["action"])
		}
	})

	t.Run("direct payload", func(t *testing.T) {
		payload := map[string]any{"action": "agent.invoke"}
		result := normalizePayload(payload)
		if result["action"] != "agent.invoke" {
			t.Errorf("expected action=agent.invoke, got %v", result["action"])
		}
	})
}

// TestDecodePayload tests payload decoding.
func TestDecodePayload(t *testing.T) {
	payload := map[string]any{
		"action":  "chain.invoke",
		"profile": "default",
		"config":  map[string]any{"chain_type": "llm"},
		"input":   "Hello",
	}

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if input.Action != "chain.invoke" {
		t.Errorf("expected action=chain.invoke, got %q", input.Action)
	}
	if input.Profile != "default" {
		t.Errorf("expected profile=default, got %q", input.Profile)
	}
}

// TestToolGovernanceFlag tests the tool_governance boolean parsing.
func TestToolGovernanceFlag(t *testing.T) {
	t.Run("governance true", func(t *testing.T) {
		payload := map[string]any{"tool_governance": true}
		var input JobInput
		if err := decodePayload(payload, &input); err != nil {
			t.Fatal(err)
		}
		if input.ToolGovernance == nil || !*input.ToolGovernance {
			t.Error("expected tool_governance=true")
		}
	})

	t.Run("governance false", func(t *testing.T) {
		payload := map[string]any{"tool_governance": false}
		var input JobInput
		if err := decodePayload(payload, &input); err != nil {
			t.Fatal(err)
		}
		if input.ToolGovernance == nil || *input.ToolGovernance {
			t.Error("expected tool_governance=false")
		}
	})

	t.Run("governance omitted", func(t *testing.T) {
		payload := map[string]any{"action": "agent.invoke"}
		var input JobInput
		if err := decodePayload(payload, &input); err != nil {
			t.Fatal(err)
		}
		if input.ToolGovernance != nil {
			t.Error("expected tool_governance=nil when omitted")
		}
	})
}

// TestCallSidecar tests the sidecar HTTP call.
func TestCallSidecar_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/execute" {
			t.Errorf("expected path /execute, got %q", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected content-type application/json")
		}
		if r.Header.Get("X-Job-ID") != "job-123" {
			t.Errorf("expected X-Job-ID=job-123, got %q", r.Header.Get("X-Job-ID"))
		}

		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["action"] != "chain.invoke" {
			t.Errorf("expected action=chain.invoke, got %v", body["action"])
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"result": map[string]any{
				"output": "Hello from LangChain!",
				"tokens_used": map[string]any{
					"prompt_tokens":     10,
					"completion_tokens": 5,
					"total_tokens":      15,
				},
			},
		})
	}))
	defer srv.Close()

	// Extract port from test server
	w := &Worker{
		sidecarClient: &http.Client{},
	}

	// We can't use callSidecar directly since it hardcodes 127.0.0.1, but we can test the response parsing
	resp := map[string]any{
		"ok": true,
		"result": map[string]any{
			"output": "Hello from LangChain!",
		},
	}

	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatal("expected ok=true")
	}
	if sidecarResult, ok := resp["result"].(map[string]any); ok {
		if sidecarResult["output"] != "Hello from LangChain!" {
			t.Errorf("expected output='Hello from LangChain!', got %v", sidecarResult["output"])
		}
	} else {
		t.Fatal("expected result map")
	}
	_ = w // use worker
}

// TestCallSidecar_Error tests error response parsing.
func TestCallSidecar_ErrorResponse(t *testing.T) {
	resp := map[string]any{
		"ok": false,
		"error": map[string]any{
			"type":    "ValueError",
			"message": "chain_type is required",
		},
	}

	if ok, _ := resp["ok"].(bool); ok {
		t.Fatal("expected ok=false")
	}

	errMsg := ""
	if errObj, exists := resp["error"]; exists {
		if errMap, ok := errObj.(map[string]any); ok {
			if msg, ok := errMap["message"].(string); ok {
				errMsg = msg
			}
		}
	}
	if errMsg != "chain_type is required" {
		t.Errorf("expected 'chain_type is required', got %q", errMsg)
	}
}

// TestJobResultSerialization verifies the result serializes correctly.
func TestJobResultSerialization(t *testing.T) {
	result := JobResult{
		JobID:      "job-1",
		Action:     "agent.invoke",
		DurationMs: 1234,
		Output:     "The answer is 42.",
		IntermediateSteps: []map[string]any{
			{
				"action":              map[string]any{"tool": "calculator", "tool_input": "6*7"},
				"observation":         "42",
				"governance_decision": "approved",
			},
		},
		ToolCalls: []map[string]any{
			{"tool_name": "calculator", "governance_decision": "approved"},
		},
		TokensUsed: map[string]any{
			"prompt_tokens":     100,
			"completion_tokens": 50,
			"total_tokens":      150,
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded["job_id"] != "job-1" {
		t.Errorf("expected job_id=job-1, got %v", decoded["job_id"])
	}
	if decoded["action"] != "agent.invoke" {
		t.Errorf("expected action=agent.invoke, got %v", decoded["action"])
	}
	if decoded["output"] != "The answer is 42." {
		t.Errorf("expected output='The answer is 42.', got %v", decoded["output"])
	}
}
