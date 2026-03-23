package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cordum/cordum/sdk/logging"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/artifacts"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/config"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/policyconstraints"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/slack"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/store"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

const posterTimeout = 45 * time.Second

type posterInput struct {
	Incident types.IncidentInput  `json:"incident"`
	Evidence types.EvidenceBundle `json:"evidence"`
	Summary  types.Summary        `json:"summary"`
}

func main() {
	logging.Init("incident-enricher")
	cfg := config.Load("poster")

	workerID := resolveWorkerID(cfg.WorkerID, cfg.Service)
	natsOpts := []nats.Option{nats.Name(workerID), nats.Timeout(5 * time.Second)}
	if tlsCfg, tlsErr := runtime.NATSTLSConfigFromEnv(); tlsErr != nil {
		slog.Error("nats tls config failed", "error", tlsErr)
		os.Exit(1)
	} else if tlsCfg != nil {
		natsOpts = append(natsOpts, nats.Secure(tlsCfg))
	}
	nc, err := nats.Connect(cfg.NATSURL, natsOpts...)
	if err != nil {
		slog.Error("nats connect failed", "error", err)
		os.Exit(1)
	}
	defer nc.Close()

	mem, err := store.New(cfg.RedisURL, cfg.DataTTL)
	if err != nil {
		slog.Error("store init failed", "error", err)
		os.Exit(1)
	}

	blobStore, err := runtime.NewRedisBlobStoreWithTTL(cfg.RedisURL, cfg.DataTTL)
	if err != nil {
		slog.Error("redis blob store init failed", "error", err)
		os.Exit(1)
	}

	gw := gatewayclient.New(cfg.GatewayURL, cfg.APIKey, cfg.TenantID)

	agent := &runtime.Agent{
		NATS:     nc,
		Store:    blobStore,
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

	handler := func(rctx runtime.Context, payload map[string]any) (types.PostResult, error) {
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
		var input posterInput
		if err := decodePayload(payload, &input); err != nil {
			return types.PostResult{}, err
		}
		if strings.TrimSpace(input.Incident.IncidentID) == "" {
			return types.PostResult{}, errors.New("missing incident_id")
		}
		cacheKey := "incident-enricher:posted:" + input.Incident.IncidentID

		callCtx, cancel := context.WithTimeout(context.Background(), posterTimeout)
		defer cancel()

		if cached, ok, err := getCachedPost(callCtx, mem.Client(), cacheKey); err != nil {
			return types.PostResult{}, err
		} else if ok {
			return cached, nil
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

		maxBytes := policyconstraints.MaxArtifactBytes(rctx.Job.GetEnv())
		switch mode {
		case "slack":
			webhook := strings.TrimSpace(input.Incident.Destination.SlackWebhookURL)
			if webhook == "" {
				webhook = cfg.SlackWebhookURL
			}
			if webhook == "" {
				return types.PostResult{}, errors.New("slack webhook url missing")
			}
			constraints, err := policyconstraints.Parse(rctx.Job.GetEnv())
			if err != nil {
				return types.PostResult{}, err
			}
			allowed, err := policyconstraints.HostAllowed(constraints, webhook)
			if err != nil {
				return types.PostResult{}, err
			}
			if !allowed {
				return types.PostResult{}, fmt.Errorf("webhook host not allowed by policy")
			}
			message := strings.TrimSpace(input.Summary.SummaryMarkdown)
			if message == "" {
				message = fmt.Sprintf("Incident %s summary ready", input.Incident.IncidentID)
			}
			slackResult, err := slack.PostWebhook(callCtx, webhook, message)
			if err != nil {
				return types.PostResult{}, err
			}
			result.Slack = slackResult
			artifactPtr, _, err := artifacts.UploadText(callCtx, gw, message, "text/plain", "audit", map[string]string{
				"kind":        "post_payload",
				"incident_id": input.Incident.IncidentID,
			}, maxBytes)
			if err != nil {
				return types.PostResult{}, err
			}
			result.ArtifactPtr = artifactPtr
		case "artifact":
			payload := map[string]any{
				"incident": input.Incident,
				"summary":  input.Summary,
			}
			artifactPtr, _, err := artifacts.UploadJSON(callCtx, gw, payload, "audit", map[string]string{
				"kind":        "post_payload",
				"incident_id": input.Incident.IncidentID,
			}, maxBytes)
			if err != nil {
				return types.PostResult{}, err
			}
			result.ArtifactPtr = artifactPtr
		default:
			return types.PostResult{}, fmt.Errorf("unsupported destination mode: %s", mode)
		}

		if err := storeCachedPost(callCtx, mem.Client(), cacheKey, result, cfg.DataTTL); err != nil {
			return types.PostResult{}, err
		}
		return result, nil
	}

	runtime.Register(agent, "job.incident-enricher.post", handler)
	runtime.Register(agent, runtime.DirectSubject(workerID), handler)

	if err := agent.Start(); err != nil {
		slog.Error("agent start failed", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go runtime.HeartbeatLoop(ctx, nc, func() ([]byte, error) {
		activeJobs := int(atomic.LoadInt32(&active))
		return runtime.HeartbeatPayload(workerID, cfg.WorkerPool, activeJobs, cfg.MaxParallelJobs, 0)
	})

	slog.Info("listening", "topic", "job.incident-enricher.post", "workerId", workerID, "pool", cfg.WorkerPool)
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
