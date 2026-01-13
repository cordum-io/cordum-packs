package llm

import (
	"context"
	"errors"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

func SummarizeOpenAI(_ context.Context, _ Settings, _ Input) (types.Summary, error) {
	return types.Summary{}, errors.New("openai summarizer not configured")
}
