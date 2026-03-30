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
