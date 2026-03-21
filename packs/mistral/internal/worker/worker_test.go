package worker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/mistral/internal/config"
	"github.com/cordum-io/cordum-packs/packs/mistral/internal/mistralapi"
)

func TestModelAllowed(t *testing.T) {
	tests := []struct {
		name  string
		cfg   config.Config
		model string
		want  bool
	}{
		{"no restrictions", config.Config{}, "mistral-large-latest", true},
		{"denied", config.Config{DeniedModels: []string{"codestral-latest"}}, "codestral-latest", false},
		{"allowed match", config.Config{AllowedModels: []string{"mistral-small-latest"}}, "mistral-small-latest", true},
		{"allowed no match", config.Config{AllowedModels: []string{"mistral-small-latest"}}, "mistral-large-latest", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsModelAllowed(tt.model); got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestNormalizePayload(t *testing.T) {
	result := normalizePayload(nil)
	if result == nil {
		t.Fatal("expected non-nil")
	}

	result = normalizePayload(map[string]any{"context": map[string]any{"action": "chat.completions"}})
	if result["action"] != "chat.completions" {
		t.Errorf("expected chat.completions, got %v", result["action"])
	}
}

func TestDecodePayload(t *testing.T) {
	var input JobInput
	err := decodePayload(map[string]any{"action": "embeddings", "profile": "default"}, &input)
	if err != nil {
		t.Fatal(err)
	}
	if input.Action != "embeddings" {
		t.Errorf("expected embeddings, got %q", input.Action)
	}
}

func TestTokenCount(t *testing.T) {
	if tokenCount(nil, true) != 0 {
		t.Error("expected 0 for nil usage")
	}

	usage := &mistralapi.Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15}
	if tokenCount(usage, true) != 10 {
		t.Errorf("expected 10, got %d", tokenCount(usage, true))
	}
	if tokenCount(usage, false) != 5 {
		t.Errorf("expected 5, got %d", tokenCount(usage, false))
	}
}

// fakeStreamReader returns valid SSE lines then an error to simulate disconnect.
type fakeStreamReader struct {
	data    string
	reader  *strings.Reader
	errOnce bool
}

func newFakeStreamReader(lines string) *fakeStreamReader {
	return &fakeStreamReader{data: lines, reader: strings.NewReader(lines)}
}

func (f *fakeStreamReader) Read(p []byte) (int, error) {
	n, err := f.reader.Read(p)
	if err == io.EOF && !f.errOnce {
		f.errOnce = true
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (f *fakeStreamReader) Close() error { return nil }

// TestStreamDisconnectDetection verifies scanner.Err() catches mid-stream disconnect.
func TestStreamDisconnectDetection(t *testing.T) {
	// Simulate a stream that delivers 2 chunks then disconnects
	sseLines := "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n"
	reader := newFakeStreamReader(sseLines)

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var textBuilder strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			if v == "[DONE]" {
				break
			}
			var chunk struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if json.Unmarshal([]byte(v), &chunk) == nil && len(chunk.Choices) > 0 {
				textBuilder.WriteString(chunk.Choices[0].Delta.Content)
			}
		}
	}

	if err := scanner.Err(); err == nil {
		t.Error("expected scanner.Err() to return an error after disconnect")
	}

	// Content accumulated before disconnect should be present
	got := textBuilder.String()
	if got != "Hello world" {
		t.Errorf("expected accumulated content %q, got %q", "Hello world", got)
	}
}

// TestStreamLargeSSEEvent verifies the 1MB buffer handles events > 64KB.
func TestStreamLargeSSEEvent(t *testing.T) {
	// Create a 100KB content string
	largeContent := strings.Repeat("x", 100*1024)
	chunk := fmt.Sprintf(`{"choices":[{"delta":{"content":"%s"}}]}`, largeContent)
	sseStream := "data: " + chunk + "\ndata: [DONE]\n"

	scanner := bufio.NewScanner(strings.NewReader(sseStream))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB buffer (the fix)

	var textBuilder strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if v, ok := strings.CutPrefix(line, "data: "); ok {
			if v == "[DONE]" {
				break
			}
			var parsed struct {
				Choices []struct {
					Delta struct {
						Content string `json:"content"`
					} `json:"delta"`
				} `json:"choices"`
			}
			if json.Unmarshal([]byte(v), &parsed) == nil && len(parsed.Choices) > 0 {
				textBuilder.WriteString(parsed.Choices[0].Delta.Content)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error on large event: %v", err)
	}

	if textBuilder.Len() != 100*1024 {
		t.Errorf("expected content length %d, got %d", 100*1024, textBuilder.Len())
	}
}

// TestStreamLargeSSEEventFailsWithSmallBuffer proves the bug existed before the fix.
func TestStreamLargeSSEEventFailsWithSmallBuffer(t *testing.T) {
	largeContent := strings.Repeat("x", 100*1024)
	chunk := fmt.Sprintf(`{"choices":[{"delta":{"content":"%s"}}]}`, largeContent)
	sseStream := "data: " + chunk + "\ndata: [DONE]\n"

	scanner := bufio.NewScanner(strings.NewReader(sseStream))
	// Default buffer — no custom size (64KB limit)

	scanned := false
	for scanner.Scan() {
		scanned = true
	}

	if scanner.Err() == nil && scanned {
		t.Error("expected scanner to fail with default buffer on 100KB event")
	}
}
