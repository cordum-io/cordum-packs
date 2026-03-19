package policy

import (
	"encoding/json"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/pic-standard/internal/picclient"
)

func TestMapResult_AllowedProceed(t *testing.T) {
	resp := picclient.VerifyResponse{
		Allowed: true,
		EvalMs:  12,
	}
	out := MapResult(resp)

	if !out.Allowed {
		t.Fatalf("expected allowed=true")
	}
	if out.Next != "proceed" {
		t.Fatalf("expected next=proceed, got %q", out.Next)
	}
	if out.EvalMs != 12 {
		t.Fatalf("expected eval_ms=12, got %d", out.EvalMs)
	}
	if out.Impact != nil {
		t.Fatalf("expected impact=nil, got %v", out.Impact)
	}
	if out.Reason != nil {
		t.Fatalf("expected reason=nil, got %v", out.Reason)
	}
}

func TestMapResult_DeniedFail(t *testing.T) {
	resp := picclient.VerifyResponse{
		Allowed: false,
		EvalMs:  5,
		Error: &picclient.VerifyError{
			Code:    "PIC_POLICY_VIOLATION",
			Message: "tool not in allowlist",
		},
	}
	out := MapResult(resp)

	if out.Allowed {
		t.Fatalf("expected allowed=false")
	}
	if out.Next != "fail" {
		t.Fatalf("expected next=fail, got %q", out.Next)
	}
	if out.Reason != "tool not in allowlist" {
		t.Fatalf("expected reason from message, got %v", out.Reason)
	}
}

func TestMapResult_DeniedFail_EmptyMessage_FallbackToCode(t *testing.T) {
	resp := picclient.VerifyResponse{
		Allowed: false,
		EvalMs:  3,
		Error: &picclient.VerifyError{
			Code:    "PIC_BRIDGE_UNREACHABLE",
			Message: "",
		},
	}
	out := MapResult(resp)

	if out.Next != "fail" {
		t.Fatalf("expected next=fail, got %q", out.Next)
	}
	if out.Reason != "code:PIC_BRIDGE_UNREACHABLE" {
		t.Fatalf("expected code fallback reason, got %v", out.Reason)
	}
}

func TestMapResult_DeniedFail_NilError(t *testing.T) {
	resp := picclient.VerifyResponse{
		Allowed: false,
		EvalMs:  1,
		Error:   nil,
	}
	out := MapResult(resp)

	if out.Next != "fail" {
		t.Fatalf("expected next=fail, got %q", out.Next)
	}
	if out.Reason != nil {
		t.Fatalf("expected reason=nil when no error, got %v", out.Reason)
	}
}

func TestMapResultWithImpact_Proceed(t *testing.T) {
	resp := picclient.VerifyResponse{Allowed: true, EvalMs: 10}
	out := MapResultWithImpact(resp, "read", []string{"money", "irreversible"})

	if out.Next != "proceed" {
		t.Fatalf("expected next=proceed, got %q", out.Next)
	}
	if out.Impact != "read" {
		t.Fatalf("expected impact=read, got %v", out.Impact)
	}
}

func TestMapResultWithImpact_RequireApproval(t *testing.T) {
	resp := picclient.VerifyResponse{Allowed: true, EvalMs: 10}
	out := MapResultWithImpact(resp, "money", []string{"money", "irreversible"})

	if out.Next != "require_approval" {
		t.Fatalf("expected next=require_approval, got %q", out.Next)
	}
	if out.Impact != "money" {
		t.Fatalf("expected impact=money, got %v", out.Impact)
	}
}

func TestMapResultWithImpact_RequireApproval_CaseInsensitive(t *testing.T) {
	resp := picclient.VerifyResponse{Allowed: true, EvalMs: 10}
	out := MapResultWithImpact(resp, "Money", []string{"money", "irreversible"})

	if out.Next != "require_approval" {
		t.Fatalf("expected case-insensitive match, got next=%q", out.Next)
	}
}

func TestMapResultWithImpact_RequireApproval_TrimmedList(t *testing.T) {
	resp := picclient.VerifyResponse{Allowed: true, EvalMs: 10}
	out := MapResultWithImpact(resp, "money", []string{" money ", "irreversible"})

	if out.Next != "require_approval" {
		t.Fatalf("expected trimmed match, got next=%q", out.Next)
	}
}

func TestMapResultWithImpact_DeniedIgnoresApproval(t *testing.T) {
	resp := picclient.VerifyResponse{
		Allowed: false,
		EvalMs:  5,
		Error: &picclient.VerifyError{
			Code:    "PIC_POLICY_VIOLATION",
			Message: "denied",
		},
	}
	out := MapResultWithImpact(resp, "money", []string{"money"})

	if out.Next != "fail" {
		t.Fatalf("denied must always fail, got next=%q", out.Next)
	}
	if out.Impact != "money" {
		t.Fatalf("expected impact=money even on deny, got %v", out.Impact)
	}
}

func TestMapResultWithImpact_EmptyImpact(t *testing.T) {
	resp := picclient.VerifyResponse{Allowed: true, EvalMs: 10}
	out := MapResultWithImpact(resp, "", []string{"money"})

	if out.Next != "proceed" {
		t.Fatalf("expected proceed with empty impact, got %q", out.Next)
	}
	if out.Impact != nil {
		t.Fatalf("expected impact=nil for empty string, got %v", out.Impact)
	}
}

func TestMapResultWithImpact_WhitespaceImpact(t *testing.T) {
	resp := picclient.VerifyResponse{Allowed: true, EvalMs: 10}
	out := MapResultWithImpact(resp, "  ", []string{"money"})

	if out.Next != "proceed" {
		t.Fatalf("expected proceed with whitespace impact, got %q", out.Next)
	}
	if out.Impact != nil {
		t.Fatalf("expected impact=nil for whitespace, got %v", out.Impact)
	}
}

func TestOutput_JSONNullableFields(t *testing.T) {
	out := Output{
		Allowed: true,
		EvalMs:  10,
		Next:    "proceed",
		Impact:  nil,
		Reason:  nil,
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"allowed", "eval_ms", "next", "impact", "reason"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("expected key %q in JSON output, missing", key)
		}
	}

	if raw["impact"] != nil {
		t.Fatalf("expected impact=null, got %v", raw["impact"])
	}
	if raw["reason"] != nil {
		t.Fatalf("expected reason=null, got %v", raw["reason"])
	}
}

func TestOutput_JSONStringFields(t *testing.T) {
	out := Output{
		Allowed: false,
		EvalMs:  5,
		Next:    "fail",
		Impact:  "money",
		Reason:  "tool not allowed",
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if raw["impact"] != "money" {
		t.Fatalf("expected impact=money, got %v", raw["impact"])
	}
	if raw["reason"] != "tool not allowed" {
		t.Fatalf("expected reason=tool not allowed, got %v", raw["reason"])
	}
}
