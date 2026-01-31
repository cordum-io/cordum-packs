package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/artifacts"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/config"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/llm"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/policyconstraints"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

const summarizerTimeout = 2 * time.Minute

type summarizerInput struct {
	Evidence types.EvidenceBundle `json:"evidence"`
}

func main() {
	cfg := config.Load("summarizer")

	workerID := runtime.ResolveWorkerID(cfg.WorkerID, cfg.Service)
	nc, err := nats.Connect(cfg.NATSURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	store, err := runtime.NewRedisBlobStoreWithTTL(cfg.RedisURL, cfg.DataTTL)
	if err != nil {
		log.Fatal(err)
	}

	gw := gatewayclient.New(cfg.GatewayURL, cfg.APIKey, cfg.TenantID)

	agent := &runtime.Agent{
		NATS:     nc,
		Store:    store,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	var (
		sem    chan struct{}
		active int32
	)
	if cfg.MaxParallelJobs > 0 {
		sem = make(chan struct{}, cfg.MaxParallelJobs)
	}

	handler := func(rctx runtime.Context, payload map[string]any) (types.Summary, error) {
		if sem != nil {
			sem <- struct{}{}
			atomic.AddInt32(&active, 1)
			defer func() {
				<-sem
				atomic.AddInt32(&active, -1)
			}()
		} else {
			atomic.AddInt32(&active, 1)
			defer atomic.AddInt32(&active, -1)
		}

		payload = normalizePayload(payload)
		var input summarizerInput
		if err := decodePayload(payload, &input); err != nil {
			return types.Summary{}, err
		}
		if input.Evidence.IncidentID == "" {
			return types.Summary{}, errors.New("missing evidence in input")
		}

		callCtx, cancel := context.WithTimeout(context.Background(), summarizerTimeout)
		defer cancel()

		redaction := policyconstraints.RedactionLevel(rctx.Job.GetEnv())
		evidenceText := collectEvidenceText(callCtx, gw, input.Evidence, cfg.LLMMaxEvidenceItems, cfg.LLMMaxEvidenceBytes)
		settings := llm.Settings{
			Provider:       cfg.LLMProvider,
			OpenAIAPIKey:   cfg.OpenAIAPIKey,
			OpenAIModel:    cfg.OpenAIModel,
			OllamaURL:      cfg.OllamaURL,
			OllamaModel:    cfg.OllamaModel,
			OllamaTemp:     cfg.OllamaTemp,
			MaxInputBytes:  cfg.LLMMaxInputBytes,
			MaxEvidence:    cfg.LLMMaxEvidenceItems,
			MaxEvidenceLen: cfg.LLMMaxEvidenceBytes,
		}
		llmInput := llm.Input{
			Bundle:   input.Evidence,
			Evidence: evidenceText,
		}
		summary, err := llm.Summarize(callCtx, settings, llmInput, redaction)
		if err != nil {
			return types.Summary{}, err
		}
		maxBytes := policyconstraints.MaxArtifactBytes(rctx.Job.GetEnv())
		ptr, _, err := artifacts.UploadText(callCtx, gw, summary.SummaryMarkdown, "text/markdown", "audit", map[string]string{
			"kind":        "summary",
			"incident_id": summary.IncidentID,
		}, maxBytes)
		if err != nil {
			return types.Summary{}, err
		}
		summary.ArtifactPtr = ptr
		return summary, nil
	}

	runtime.Register(agent, "job.incident-enricher.summarize", handler)
	runtime.Register(agent, runtime.DirectSubject(workerID), handler)

	if err := agent.Start(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go runtime.HeartbeatLoop(ctx, nc, func() ([]byte, error) {
		activeJobs := int(atomic.LoadInt32(&active))
		return runtime.HeartbeatPayload(workerID, cfg.WorkerPool, activeJobs, cfg.MaxParallelJobs, 0)
	})

	log.Printf("summarizer listening for job.incident-enricher.summarize (worker_id=%s pool=%s)", workerID, cfg.WorkerPool)
	<-ctx.Done()
}

func normalizePayload(payload map[string]any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	if ctxPayload, ok := payload["context"].(map[string]any); ok {
		return ctxPayload
	}
	return payload
}

func decodePayload(payload map[string]any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func collectEvidenceText(ctx context.Context, gw *gatewayclient.Client, bundle types.EvidenceBundle, maxItems, maxBytes int) []llm.EvidenceText {
	if maxItems <= 0 {
		maxItems = 4
	}
	if maxBytes <= 0 {
		maxBytes = 32768
	}
	var out []llm.EvidenceText
	total := 0
	for _, item := range bundle.Evidence {
		if item.ArtifactPtr == "" {
			continue
		}
		if len(out) >= maxItems || total >= maxBytes {
			break
		}
		content, meta, err := gw.GetArtifact(ctx, item.ArtifactPtr)
		if err != nil {
			log.Printf("summarizer: fetch artifact %s: %v", item.ArtifactPtr, err)
			continue
		}
		contentType := item.ContentType
		if contentType == "" {
			if v, ok := meta["content_type"].(string); ok {
				contentType = v
			}
		}
		text := extractEvidenceText(content, contentType)
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		remaining := maxBytes - total
		if remaining <= 0 {
			break
		}
		text = truncateToBytes(text, remaining)
		total += len(text)
		out = append(out, llm.EvidenceText{
			Kind:        item.Kind,
			Title:       item.Title,
			ArtifactPtr: item.ArtifactPtr,
			ContentType: contentType,
			Content:     text,
		})
	}
	return out
}

func extractEvidenceText(content []byte, contentType string) string {
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return ""
	}
	if strings.Contains(strings.ToLower(contentType), "json") || strings.HasPrefix(trimmed, "{") {
		var payload map[string]any
		if err := json.Unmarshal(content, &payload); err == nil {
			if msg := nestedString(payload, "raw", "message"); msg != "" {
				return msg
			}
			if msg := nestedString(payload, "incident", "raw", "message"); msg != "" {
				return msg
			}
			if msg := stringField(payload, "message"); msg != "" {
				return msg
			}
		}
	}
	return trimmed
}

func nestedString(payload map[string]any, path ...string) string {
	current := any(payload)
	for _, key := range path {
		obj, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = obj[key]
		if !ok {
			return ""
		}
	}
	if val, ok := current.(string); ok {
		return strings.TrimSpace(val)
	}
	return ""
}

func stringField(payload map[string]any, key string) string {
	val, ok := payload[key]
	if !ok {
		return ""
	}
	str, ok := val.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
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
