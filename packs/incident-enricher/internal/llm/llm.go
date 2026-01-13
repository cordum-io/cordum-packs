package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

type Settings struct {
	Provider       string
	OpenAIAPIKey   string
	OpenAIModel    string
	OllamaURL      string
	OllamaModel    string
	OllamaTemp     float64
	MaxInputBytes  int
	MaxEvidence    int
	MaxEvidenceLen int
}

type EvidenceText struct {
	Kind        string
	Title       string
	ArtifactPtr string
	ContentType string
	Content     string
}

type Input struct {
	Bundle   types.EvidenceBundle
	Evidence []EvidenceText
}

func Summarize(ctx context.Context, settings Settings, input Input, redactionLevel string) (types.Summary, error) {
	redaction := strings.ToLower(strings.TrimSpace(redactionLevel))
	if redaction != "" && redaction != "none" {
		return SummarizeMock(input, redactionLevel), nil
	}
	provider := strings.ToLower(strings.TrimSpace(settings.Provider))
	switch provider {
	case "", "mock":
		return SummarizeMock(input, redactionLevel), nil
	case "openai":
		return SummarizeOpenAI(ctx, settings, input)
	case "ollama":
		return SummarizeOllama(ctx, settings, input)
	default:
		return types.Summary{}, fmt.Errorf("unsupported llm provider: %s", settings.Provider)
	}
}
