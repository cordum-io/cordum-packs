package worker

import "testing"

func TestNormalizePayload(t *testing.T) {
	if normalizePayload(nil) == nil {
		t.Fatal("expected non-nil")
	}
	r := normalizePayload(map[string]any{"context": map[string]any{"action": "groupchat"}})
	if r["action"] != "groupchat" {
		t.Errorf("expected groupchat, got %v", r["action"])
	}
}

func TestDecodePayload(t *testing.T) {
	var input JobInput
	if err := decodePayload(map[string]any{"action": "code", "profile": "default"}, &input); err != nil {
		t.Fatal(err)
	}
	if input.Action != "code" {
		t.Errorf("expected code, got %q", input.Action)
	}
}

func TestToolGovernanceFlag(t *testing.T) {
	payload := map[string]any{"tool_governance": true}
	var input JobInput
	decodePayload(payload, &input)
	if input.ToolGovernance == nil || !*input.ToolGovernance {
		t.Error("expected tool_governance=true")
	}

	payload2 := map[string]any{"action": "agent"}
	var input2 JobInput
	decodePayload(payload2, &input2)
	if input2.ToolGovernance != nil {
		t.Error("expected nil when omitted")
	}
}
