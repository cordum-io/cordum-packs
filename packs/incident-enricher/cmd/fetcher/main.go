package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cordum/cordum/sdk/logging"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/config"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/incidents"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/policyconstraints"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
)

const fetcherTimeout = 45 * time.Second

func main() {
	logging.Init("incident-enricher")
	cfg := config.Load("fetcher")

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

	store, err := runtime.NewRedisBlobStoreWithTTL(cfg.RedisURL, cfg.DataTTL)
	if err != nil {
		slog.Error("redis blob store init failed", "error", err)
		os.Exit(1)
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

	handler := func(rctx runtime.Context, payload map[string]any) (types.EvidenceBundle, error) {
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
		var input types.IncidentInput
		if err := decodePayload(payload, &input); err != nil {
			return types.EvidenceBundle{}, err
		}

		maxBytes := policyconstraints.MaxArtifactBytes(rctx.Job.GetEnv())
		callCtx, cancel := context.WithTimeout(context.Background(), fetcherTimeout)
		defer cancel()
		bundle, _, err := incidents.MockEvidence(callCtx, gw, input, maxBytes)
		if err != nil {
			return types.EvidenceBundle{}, err
		}
		return bundle, nil
	}

	runtime.Register(agent, "job.incident-enricher.fetch", handler)
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

	slog.Info("listening", "topic", "job.incident-enricher.fetch", "workerId", workerID, "pool", cfg.WorkerPool)
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
