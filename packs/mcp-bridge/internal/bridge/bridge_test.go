package bridge

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/mcp-bridge/internal/mcp"
)

func TestNormalizePayload(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    map[string]any
	}{
		{
			name:    "nil payload returns empty map",
			payload: nil,
			want:    map[string]any{},
		},
		{
			name:    "payload without context key returns as-is",
			payload: map[string]any{"tool": "echo", "args": "hello"},
			want:    map[string]any{"tool": "echo", "args": "hello"},
		},
		{
			name: "payload with context key extracts nested map",
			payload: map[string]any{
				"context": map[string]any{"tool": "echo", "args": "hello"},
			},
			want: map[string]any{"tool": "echo", "args": "hello"},
		},
		{
			name:    "payload with non-map context returns as-is",
			payload: map[string]any{"context": "not-a-map", "other": "value"},
			want:    map[string]any{"context": "not-a-map", "other": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePayload(tt.payload)
			if got == nil {
				t.Fatal("normalizePayload returned nil, want non-nil map")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("length mismatch: got %d, want %d", len(got), len(tt.want))
			}
			for k, wantVal := range tt.want {
				gotVal, ok := got[k]
				if !ok {
					t.Errorf("missing key %q", k)
					continue
				}
				if gotVal != wantVal {
					t.Errorf("key %q: got %v, want %v", k, gotVal, wantVal)
				}
			}
		})
	}
}

func TestExtractToolCall(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		wantName string
		wantArgs map[string]any
		wantErr  string
	}{
		{
			name:    "nil payload returns error",
			payload: nil,
			wantErr: "tool context missing",
		},
		{
			name: "payload with tool name and args",
			payload: map[string]any{
				"tool": "cordum.workflow.run",
				"args": map[string]any{"workflow_id": "wf-123"},
			},
			wantName: "cordum.workflow.run",
			wantArgs: map[string]any{"workflow_id": "wf-123"},
		},
		{
			name: "payload with context wrapper extracts tool",
			payload: map[string]any{
				"context": map[string]any{
					"tool": "cordum.workflow.run",
					"args": map[string]any{"workflow_id": "wf-456"},
				},
			},
			wantName: "cordum.workflow.run",
			wantArgs: map[string]any{"workflow_id": "wf-456"},
		},
		{
			name:    "payload without tool name returns error",
			payload: map[string]any{"args": map[string]any{"key": "val"}},
			wantErr: "tool name missing",
		},
		{
			name:     "payload with tool but no args returns empty args map",
			payload:  map[string]any{"tool": "cordum.workflow.list"},
			wantName: "cordum.workflow.list",
			wantArgs: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, args, err := extractToolCall(tt.payload)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("error mismatch: got %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if name != tt.wantName {
				t.Errorf("name: got %q, want %q", name, tt.wantName)
			}
			if len(args) != len(tt.wantArgs) {
				t.Fatalf("args length mismatch: got %d, want %d", len(args), len(tt.wantArgs))
			}
			for k, wantVal := range tt.wantArgs {
				gotVal, ok := args[k]
				if !ok {
					t.Errorf("args missing key %q", k)
					continue
				}
				if gotVal != wantVal {
					t.Errorf("args[%q]: got %v, want %v", k, gotVal, wantVal)
				}
			}
		})
	}
}

func TestJsonContent(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		value    any
		wantURI  string
		wantMIME string
		wantText string
	}{
		{
			name:     "string value",
			uri:      "cordum://workflows/wf-1",
			value:    "hello",
			wantURI:  "cordum://workflows/wf-1",
			wantMIME: "application/json",
			wantText: `"hello"`,
		},
		{
			name:     "map value gets JSON-encoded",
			uri:      "cordum://runs/run-1",
			value:    map[string]any{"status": "completed", "steps": 3.0},
			wantURI:  "cordum://runs/run-1",
			wantMIME: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jsonContent(tt.uri, tt.value)

			if got.URI != tt.wantURI {
				t.Errorf("URI: got %q, want %q", got.URI, tt.wantURI)
			}
			if got.MimeType != tt.wantMIME {
				t.Errorf("MimeType: got %q, want %q", got.MimeType, tt.wantMIME)
			}

			if tt.wantText != "" {
				if got.Text != tt.wantText {
					t.Errorf("Text: got %q, want %q", got.Text, tt.wantText)
				}
			} else {
				// For non-string values, verify the text is valid JSON that
				// round-trips to the same structure.
				var parsed map[string]any
				if err := json.Unmarshal([]byte(got.Text), &parsed); err != nil {
					t.Fatalf("Text is not valid JSON: %v\nText: %s", err, got.Text)
				}
				orig, ok := tt.value.(map[string]any)
				if !ok {
					t.Fatal("test misconfigured: non-string wantText requires map value")
				}
				for k, wantVal := range orig {
					gotVal, exists := parsed[k]
					if !exists {
						t.Errorf("parsed JSON missing key %q", k)
						continue
					}
					// json.Unmarshal decodes numbers as float64, so compare with Sprint.
					if fmt.Sprintf("%v", gotVal) != fmt.Sprintf("%v", wantVal) {
						t.Errorf("parsed JSON key %q: got %v, want %v", k, gotVal, wantVal)
					}
				}
			}
		})
	}

	// Verify the result satisfies the mcp.ResourceContent struct shape.
	_ = mcp.ResourceContent{}
}

// TestAuditLogTurnToolRegistered pins the cordum.audit.log_turn tool in
// the bridge's advertised catalogue. Adapters look this name up via
// list_tools; if it's missing they fall back to a debug log rather than
// raising, so a silent rename would lose audit fidelity without any
// test catching it.
func TestAuditLogTurnToolRegistered(t *testing.T) {
	b := &Bridge{}
	tools := b.buildTools()

	var found *mcp.Tool
	for i := range tools {
		if tools[i].Name == "cordum.audit.log_turn" {
			found = &tools[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("cordum.audit.log_turn tool not found in bridge catalogue")
	}

	schema := found.InputSchema
	if schema == nil {
		t.Fatalf("inputSchema is nil")
	}
	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatalf("required is not []string, got %T", schema["required"])
	}
	wantRequired := map[string]bool{"session_id": true, "turn": true}
	for _, r := range required {
		if !wantRequired[r] {
			t.Errorf("unexpected required field %q", r)
		}
		delete(wantRequired, r)
	}
	if len(wantRequired) > 0 {
		t.Errorf("missing required fields: %v", wantRequired)
	}
}

// TestExecuteToolAuditLogTurn exercises the tool-body no-op path for
// cordum.audit.log_turn: session_id required, turn required to be an
// object, successful invocation returns a status envelope. The
// gateway's MCP middleware emits the SIEMEvent for the enclosing
// tools/call, so the body intentionally does no gateway I/O.
func TestExecuteToolAuditLogTurn(t *testing.T) {
	cases := []struct {
		name    string
		args    map[string]any
		wantErr string
	}{
		{
			name: "happy path",
			args: map[string]any{
				"session_id": "sess-1",
				"turn":       map[string]any{"kind": "tool_call", "tool_name": "echo"},
			},
		},
		{
			name:    "missing session_id",
			args:    map[string]any{"turn": map[string]any{"kind": "x"}},
			wantErr: "session_id required",
		},
		{
			name:    "turn not an object",
			args:    map[string]any{"session_id": "sess-1", "turn": "not-a-map"},
			wantErr: "turn must be an object",
		},
	}

	b := &Bridge{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := b.executeTool(t.Context(), "cordum.audit.log_turn", tc.args)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got result %+v", tc.wantErr, result)
				}
				if err.Error() != tc.wantErr {
					t.Errorf("error: got %q, want %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			envelope, ok := result.(map[string]any)
			if !ok {
				t.Fatalf("result is not a map, got %T", result)
			}
			if envelope["status"] != "recorded" {
				t.Errorf("status: got %v, want %q", envelope["status"], "recorded")
			}
			if envelope["session_id"] != "sess-1" {
				t.Errorf("session_id: got %v, want %q", envelope["session_id"], "sess-1")
			}
		})
	}
}
