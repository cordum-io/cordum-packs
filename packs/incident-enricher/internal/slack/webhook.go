package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

func PostWebhook(ctx context.Context, webhookURL string, message string) (*types.SlackResult, error) {
	payload := map[string]string{"text": message}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal slack payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("build slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := strings.TrimSpace(string(body))
	result := &types.SlackResult{OK: resp.StatusCode >= 200 && resp.StatusCode < 300}
	if result.OK && (text == "" || text == "ok") {
		result.OK = true
		return result, nil
	}
	result.OK = false
	if text == "" {
		text = resp.Status
	}
	result.Error = text
	return result, fmt.Errorf("slack webhook error: %s", text)
}
