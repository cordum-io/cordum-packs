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

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum-io/cap/v2/sdk/go/worker"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/artifacts"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/config"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/policyconstraints"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/slack"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/store"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

type posterInput struct {
	Incident types.IncidentInput  `json:"incident"`
	Evidence types.EvidenceBundle `json:"evidence"`
	Summary  types.Summary        `json:"summary"`
}

func main() {
	cfg := config.Load("poster")

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
		var input posterInput
		if err := mem.GetContextJSON(ctx, ctxPtr, &input); err != nil {
			return nil, err
		}
		if strings.TrimSpace(input.Incident.IncidentID) == "" {
			return nil, errors.New("missing incident_id")
		}
		cacheKey := "incident-enricher:posted:" + input.Incident.IncidentID
		if cached, ok, err := getCachedPost(ctx, mem.Client(), cacheKey); err != nil {
			return nil, err
		} else if ok {
			return buildResult(ctx, mem, cfg, req, cached, start)
		}

		mode := strings.ToLower(strings.TrimSpace(input.Incident.Destination.Mode))
		if mode == "" {
			mode = "artifact"
		}
		result := types.PostResult{
			IncidentID: input.Incident.IncidentID,
			Mode:       mode,
			PostedAt:   time.Now().UTC().Format(time.RFC3339),
		}

		maxBytes := policyconstraints.MaxArtifactBytes(req.Env)
		switch mode {
		case "slack":
			webhook := strings.TrimSpace(input.Incident.Destination.SlackWebhookURL)
			if webhook == "" {
				webhook = cfg.SlackWebhookURL
			}
			if webhook == "" {
				return nil, errors.New("slack webhook url missing")
			}
			constraints, err := policyconstraints.Parse(req.Env)
			if err != nil {
				return nil, err
			}
			allowed, err := policyconstraints.HostAllowed(constraints, webhook)
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, fmt.Errorf("webhook host not allowed by policy")
			}
			message := strings.TrimSpace(input.Summary.SummaryMarkdown)
			if message == "" {
				message = fmt.Sprintf("Incident %s summary ready", input.Incident.IncidentID)
			}
			slackResult, err := slack.PostWebhook(ctx, webhook, message)
			if err != nil {
				return nil, err
			}
			result.Slack = slackResult
			artifactPtr, _, err := artifacts.UploadText(ctx, gw, message, "text/plain", "audit", map[string]string{
				"kind":       "post_payload",
				"incident_id": input.Incident.IncidentID,
			}, maxBytes)
			if err != nil {
				return nil, err
			}
			result.ArtifactPtr = artifactPtr
		case "artifact":
			payload := map[string]any{
				"incident": input.Incident,
				"summary":  input.Summary,
			}
			artifactPtr, _, err := artifacts.UploadJSON(ctx, gw, payload, "audit", map[string]string{
				"kind":       "post_payload",
				"incident_id": input.Incident.IncidentID,
			}, maxBytes)
			if err != nil {
				return nil, err
			}
			result.ArtifactPtr = artifactPtr
		default:
			return nil, fmt.Errorf("unsupported destination mode: %s", mode)
		}

		if err := storeCachedPost(ctx, mem.Client(), cacheKey, result, cfg.DataTTL); err != nil {
			return nil, err
		}
		return buildResult(ctx, mem, cfg, req, result, start)
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

	log.Printf("poster listening on %s for job.incident-enricher.post (worker_id=%s pool=%s)", subject, cfg.WorkerID, cfg.WorkerPool)
	<-ctx.Done()
}

func getCachedPost(ctx context.Context, client *redis.Client, key string) (types.PostResult, bool, error) {
	data, err := client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return types.PostResult{}, false, nil
		}
		return types.PostResult{}, false, err
	}
	var result types.PostResult
	if err := json.Unmarshal(data, &result); err != nil {
		return types.PostResult{}, false, err
	}
	return result, true, nil
}

func storeCachedPost(ctx context.Context, client *redis.Client, key string, result types.PostResult, ttl time.Duration) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return client.Set(ctx, key, data, ttl).Err()
}

func buildResult(ctx context.Context, mem *store.Store, cfg config.Env, req *agentv1.JobRequest, result types.PostResult, start time.Time) (*agentv1.JobResult, error) {
	resultPtr, err := mem.PutResultJSON(ctx, req.GetJobId(), result)
	if err != nil {
		return nil, err
	}
	artifactPtrs := []string{}
	if result.ArtifactPtr != "" {
		artifactPtrs = append(artifactPtrs, result.ArtifactPtr)
	}
	return &agentv1.JobResult{
		JobId:        req.GetJobId(),
		Status:       agentv1.JobStatus_JOB_STATUS_SUCCEEDED,
		ResultPtr:    resultPtr,
		WorkerId:     cfg.WorkerID,
		ExecutionMs:  time.Since(start).Milliseconds(),
		ArtifactPtrs: artifactPtrs,
	}, nil
}
