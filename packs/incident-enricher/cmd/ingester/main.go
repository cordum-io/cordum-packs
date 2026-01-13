package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/config"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

const defaultAddr = ":8088"

func main() {
	cfg := config.Load("ingester")
	gw := gatewayclient.New(cfg.GatewayURL, cfg.APIKey)

	addr := strings.TrimSpace(os.Getenv("INGESTER_ADDR"))
	if addr == "" {
		addr = defaultAddr
	}
	workflowID := strings.TrimSpace(os.Getenv("INGESTER_WORKFLOW_ID"))
	if workflowID == "" {
		workflowID = "incident-enricher.enrich"
	}
	defaultMode := strings.TrimSpace(os.Getenv("DEFAULT_DESTINATION_MODE"))
	if defaultMode == "" {
		defaultMode = "artifact"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhook/mock", func(w http.ResponseWriter, r *http.Request) {
		handleWebhook(w, r, gw, workflowID, defaultMode, cfg.SlackWebhookURL, "mock")
	})
	mux.HandleFunc("/webhook/pagerduty", func(w http.ResponseWriter, r *http.Request) {
		handleWebhook(w, r, gw, workflowID, defaultMode, cfg.SlackWebhookURL, "pagerduty")
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("ingester listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func handleWebhook(w http.ResponseWriter, r *http.Request, gw *gatewayclient.Client, workflowID, defaultMode, defaultWebhook, system string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	input := types.IncidentInput{}
	if err := json.Unmarshal(body, &input); err == nil {
		if input.IncidentID != "" && input.Source.System != "" && input.Destination.Mode != "" {
			if input.Raw == nil {
				input.Raw = raw
			}
		} else {
			input = buildIncidentInput(raw, defaultMode, defaultWebhook, system)
		}
	} else {
		input = buildIncidentInput(raw, defaultMode, defaultWebhook, system)
	}

	idempotency := idempotencyKeyFromRequest(r)
	runID, err := gw.StartRun(r.Context(), workflowID, toMap(input), idempotency)
	if err != nil {
		log.Printf("start run failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"run_id": runID})
}

func buildIncidentInput(raw map[string]any, defaultMode, defaultWebhook, system string) types.IncidentInput {
	incidentID := stringField(raw["incident_id"])
	if incidentID == "" {
		incidentID = randomID("inc")
	}
	return types.IncidentInput{
		IncidentID: incidentID,
		Title:      stringField(raw["title"]),
		Severity:   stringField(raw["severity"]),
		Source: types.SourceInfo{
			System: system,
			URL:    stringField(raw["url"]),
		},
		Raw: raw,
		Destination: types.Destination{
			Mode:            defaultMode,
			SlackWebhookURL: defaultWebhook,
		},
	}
}

func idempotencyKeyFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	candidates := []string{
		r.Header.Get("Idempotency-Key"),
		r.Header.Get("X-Idempotency-Key"),
		r.URL.Query().Get("idempotency_key"),
		r.URL.Query().Get("idempotency-key"),
	}
	for _, raw := range candidates {
		if val := strings.TrimSpace(raw); val != "" {
			return val
		}
	}
	return ""
}

func stringField(raw any) string {
	if raw == nil {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func randomID(prefix string) string {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(buf))
}

func toMap(input types.IncidentInput) map[string]any {
	out := map[string]any{}
	data, _ := json.Marshal(input)
	_ = json.Unmarshal(data, &out)
	return out
}
