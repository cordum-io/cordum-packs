package artifacts

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
)

func UploadJSON(ctx context.Context, client *gatewayclient.Client, payload any, retention string, labels map[string]string, maxBytes int64) (string, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", 0, fmt.Errorf("marshal artifact json: %w", err)
	}
	return client.PutArtifact(ctx, data, "application/json", retention, labels, maxBytes)
}

func UploadText(ctx context.Context, client *gatewayclient.Client, text, contentType, retention string, labels map[string]string, maxBytes int64) (string, int, error) {
	if contentType == "" {
		contentType = "text/plain"
	}
	return client.PutArtifact(ctx, []byte(text), contentType, retention, labels, maxBytes)
}
