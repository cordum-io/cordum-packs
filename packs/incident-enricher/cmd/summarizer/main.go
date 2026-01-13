package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum-io/cap/v2/sdk/go/worker"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/artifacts"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/config"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/llm"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/policyconstraints"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/store"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
	"github.com/nats-io/nats.go"
)

type summarizerInput struct {
	Evidence types.EvidenceBundle `json:"evidence"`
}

func main() {
	cfg := config.Load("summarizer")

	nc, err := nats.Connect(cfg.NATSURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	mem, err := store.New(cfg.RedisURL, cfg.DataTTL)
	if err != nil {
		log.Fatal(err)
	}

	gw := gatewayclient.New(cfg.GatewayURL, cfg.APIKey)

	handler := func(ctx context.Context, req *agentv1.JobRequest) (*agentv1.JobResult, error) {
		start := time.Now()
		ctxPtr := req.GetContextPtr()
		if ctxPtr == "" && req.Env != nil {
			ctxPtr = req.Env["context_ptr"]
		}
		var input summarizerInput
		if err := mem.GetContextJSON(ctx, ctxPtr, &input); err != nil {
			return nil, err
		}
		if input.Evidence.IncidentID == "" {
			return nil, errors.New("missing evidence in input")
		}
		redaction := policyconstraints.RedactionLevel(req.Env)
		evidenceText := collectEvidenceText(ctx, gw, input.Evidence, cfg.LLMMaxEvidenceItems, cfg.LLMMaxEvidenceBytes)
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
		summary, err := llm.Summarize(ctx, settings, llmInput, redaction)
		if err != nil {
			return nil, err
		}
		maxBytes := policyconstraints.MaxArtifactBytes(req.Env)
		ptr, _, err := artifacts.UploadText(ctx, gw, summary.SummaryMarkdown, "text/markdown", "audit", map[string]string{
			"kind":        "summary",
			"incident_id": summary.IncidentID,
		}, maxBytes)
		if err != nil {
			return nil, err
		}
		summary.ArtifactPtr = ptr

		resultPtr, err := mem.PutResultJSON(ctx, req.GetJobId(), summary)
		if err != nil {
			return nil, err
		}
		return &agentv1.JobResult{
			JobId:        req.GetJobId(),
			Status:       agentv1.JobStatus_JOB_STATUS_SUCCEEDED,
			ResultPtr:    resultPtr,
			WorkerId:     cfg.WorkerID,
			ExecutionMs:  time.Since(start).Milliseconds(),
			ArtifactPtrs: []string{ptr},
		}, nil
	}

	subject := fmt.Sprintf("worker.%s.jobs", cfg.WorkerID)
	w := &worker.Worker{
		NATS:     nc,
		Subject:  subject,
		Handler:  handler,
		SenderID: cfg.WorkerID,
	}
	if err := w.Start(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go worker.HeartbeatLoop(ctx, nc, func() ([]byte, error) {
		return worker.HeartbeatPayload(cfg.WorkerID, cfg.WorkerPool, 0, cfg.MaxParallelJobs, 0)
	})

	log.Printf("summarizer listening on %s for job.incident-enricher.summarize (worker_id=%s pool=%s)", subject, cfg.WorkerID, cfg.WorkerPool)
	<-ctx.Done()
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
