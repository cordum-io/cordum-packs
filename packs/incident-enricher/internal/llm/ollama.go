package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Format   string          `json:"format,omitempty"`
	Options  map[string]any  `json:"options,omitempty"`
}

type ollamaResponse struct {
	Message ollamaMessage `json:"message"`
	Done    bool          `json:"done"`
	Error   string        `json:"error,omitempty"`
}

type summaryPayload struct {
	SummaryMarkdown string   `json:"summary_md"`
	Highlights      []string `json:"highlights,omitempty"`
	ActionItems     []string `json:"action_items,omitempty"`
	Confidence      float64  `json:"confidence,omitempty"`
}

func SummarizeOllama(ctx context.Context, settings Settings, input Input) (types.Summary, error) {
	model := strings.TrimSpace(settings.OllamaModel)
	if model == "" {
		return types.Summary{}, errors.New("OLLAMA_MODEL is required")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(settings.OllamaURL), "/")
	if baseURL == "" {
		return types.Summary{}, errors.New("OLLAMA_URL is required")
	}
	reqPayload := ollamaRequest{
		Model:  model,
		Stream: false,
		Format: "json",
		Messages: []ollamaMessage{
			{Role: "system", Content: ollamaSystemPrompt()},
			{Role: "user", Content: buildUserPrompt(input, settings.MaxInputBytes)},
		},
	}
	if settings.OllamaTemp > 0 {
		reqPayload.Options = map[string]any{
			"temperature": settings.OllamaTemp,
		}
	}
	payload, err := json.Marshal(reqPayload)
	if err != nil {
		return types.Summary{}, fmt.Errorf("marshal request: %w", err)
	}

	httpClient := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/chat", bytes.NewReader(payload))
	if err != nil {
		return types.Summary{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return types.Summary{}, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	var response ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return types.Summary{}, fmt.Errorf("decode response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error != "" {
			return types.Summary{}, fmt.Errorf("ollama error: %s", response.Error)
		}
		return types.Summary{}, fmt.Errorf("ollama http %d", resp.StatusCode)
	}
	if response.Error != "" {
		return types.Summary{}, fmt.Errorf("ollama error: %s", response.Error)
	}
	content := strings.TrimSpace(response.Message.Content)
	if content == "" {
		return types.Summary{}, errors.New("ollama response empty")
	}
	summary := types.Summary{
		IncidentID: input.Bundle.IncidentID,
		Model:      "ollama:" + model,
	}
	if payload, ok := parseSummaryJSON(content); ok {
		summary.SummaryMarkdown = payload.SummaryMarkdown
		summary.Highlights = payload.Highlights
		summary.ActionItems = payload.ActionItems
		summary.Confidence = payload.Confidence
	}
	if summary.SummaryMarkdown == "" {
		summary.SummaryMarkdown = content
	}
	return summary, nil
}

func ollamaSystemPrompt() string {
	return strings.Join([]string{
		"You are an incident analysis assistant.",
		"Use only the provided evidence for factual claims. If unsure, say \"unknown\".",
		"Respond with valid JSON only (no code fences, no triple quotes, no markdown).",
		"Use \\n for newlines inside summary_md.",
		"Required keys: summary_md (string), highlights (array of strings), action_items (array of strings), confidence (0-1).",
		"summary_md must be detailed and include these sections:",
		"- Summary: explain what happened in plain language.",
		"- Interpretation: explain what the error means in context.",
		"- Evidence: 2-4 short quoted lines from the evidence (verbatim).",
		"- Hypotheses: possible causes, clearly labeled as hypotheses.",
		"- Next steps: concrete checks or fixes.",
		"highlights and action_items must be arrays of short strings (no objects).",
	}, "\n")
}

func buildUserPrompt(input Input, maxBytes int) string {
	var b strings.Builder
	b.WriteString("Incident metadata:\n")
	if input.Bundle.IncidentID != "" {
		b.WriteString("- id: " + input.Bundle.IncidentID + "\n")
	}
	if input.Bundle.CollectedAt != "" {
		b.WriteString("- collected_at: " + input.Bundle.CollectedAt + "\n")
	}
	if len(input.Bundle.NormalizedContext) > 0 {
		if data, err := json.Marshal(input.Bundle.NormalizedContext); err == nil {
			b.WriteString("- context: " + string(data) + "\n")
		}
	}
	if len(input.Evidence) == 0 {
		b.WriteString("\nEvidence: none\n")
	} else {
		b.WriteString("\nEvidence:\n")
		for i, item := range input.Evidence {
			b.WriteString(fmt.Sprintf("[%d] kind=%s title=%s content_type=%s\n", i+1, item.Kind, item.Title, item.ContentType))
			b.WriteString(item.Content)
			b.WriteString("\n\n")
		}
	}
	raw := b.String()
	return truncateToBytes(raw, maxBytes)
}

func truncateToBytes(value string, maxBytes int) string {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	truncated := value[:maxBytes]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

func parseSummaryJSON(raw string) (summaryPayload, bool) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "```") {
		trimmed = strings.TrimPrefix(trimmed, "```")
		if idx := strings.Index(trimmed, "\n"); idx >= 0 {
			trimmed = trimmed[idx+1:]
		}
		if fence := strings.LastIndex(trimmed, "```"); fence >= 0 {
			trimmed = trimmed[:fence]
		}
		trimmed = strings.TrimSpace(trimmed)
	}
	var payload summaryPayload
	if err := json.Unmarshal([]byte(trimmed), &payload); err == nil {
		normalizeSummaryPayload(&payload)
		return payload, true
	}
	start := strings.Index(trimmed, "{")
	end := strings.LastIndex(trimmed, "}")
	if start >= 0 && end > start {
		if err := json.Unmarshal([]byte(trimmed[start:end+1]), &payload); err == nil {
			normalizeSummaryPayload(&payload)
			return payload, true
		}
	}
	return summaryPayload{}, false
}

func normalizeSummaryPayload(payload *summaryPayload) {
	if payload.Confidence < 0 {
		payload.Confidence = 0
	}
	if payload.Confidence > 1 {
		payload.Confidence = 1
	}
}
