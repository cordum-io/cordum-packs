package worker

import (
	"strings"
	"testing"
)

func TestDecodePayload(t *testing.T) {
	payload := map[string]any{"message": "hello", "author": "cordum"}
	var input HelloInput
	if err := decodePayload(payload, &input); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if input.Message != "hello" {
		t.Fatalf("expected message")
	}
	if input.Author != "cordum" {
		t.Fatalf("expected author")
	}
}

func TestEchoFormatting(t *testing.T) {
	msg := "  hello world  "
	result := HelloOutput{
		Echo: strings.TrimSpace(msg),
	}
	if result.Echo != "hello world" {
		t.Fatalf("expected trimmed echo")
	}
}
