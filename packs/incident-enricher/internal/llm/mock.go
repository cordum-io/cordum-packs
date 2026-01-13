package llm

import (
	"fmt"
	"strings"
	"time"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

func SummarizeMock(input Input, redactionLevel string) types.Summary {
	summary := types.Summary{
		IncidentID: input.Bundle.IncidentID,
		Model:      "mock",
		Confidence: 0.4,
	}
	redaction := strings.ToLower(strings.TrimSpace(redactionLevel))
	if redaction != "" && redaction != "none" {
		summary.SummaryMarkdown = "Summary redacted by policy."
		summary.Highlights = []string{"redacted"}
		summary.ActionItems = []string{"request approval to view full details"}
		summary.Model = "mock-redacted"
		return summary
	}
	count := len(input.Bundle.Evidence)
	summary.SummaryMarkdown = fmt.Sprintf("Incident %s summary: collected %d evidence item(s) at %s.", input.Bundle.IncidentID, count, time.Now().UTC().Format(time.RFC3339))
	if count > 0 {
		summary.Highlights = []string{fmt.Sprintf("%d evidence item(s) collected", count)}
	}
	summary.ActionItems = []string{"review evidence bundle", "confirm next steps"}
	return summary
}
