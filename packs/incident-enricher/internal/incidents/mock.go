package incidents

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

func MockEvidence(ctx context.Context, gw *gatewayclient.Client, input types.IncidentInput, maxArtifactBytes int64) (types.EvidenceBundle, []string, error) {
	safe := input
	safe.Destination.SlackWebhookURL = ""
	payload, err := json.Marshal(safe)
	if err != nil {
		return types.EvidenceBundle{}, nil, err
	}
	ptr, size, err := gw.PutArtifact(ctx, payload, "application/json", "audit", map[string]string{
		"kind":        "incident",
		"incident_id": input.IncidentID,
	}, maxArtifactBytes)
	if err != nil {
		return types.EvidenceBundle{}, nil, err
	}
	bundle := types.EvidenceBundle{
		IncidentID: input.IncidentID,
		Evidence: []types.EvidenceItem{
			{
				Kind:        "incident.raw",
				Title:       "incident payload",
				ArtifactPtr: ptr,
				ContentType: "application/json",
				Bytes:       int64(size),
			},
		},
		NormalizedContext: map[string]any{
			"title":    input.Title,
			"severity": input.Severity,
			"source":   input.Source.System,
		},
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return bundle, []string{ptr}, nil
}
