package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum-io/cap/v2/sdk/go/worker"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/config"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/incidents"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/policyconstraints"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/store"
	"github.com/cordum-io/cordum-packs/packs/incident-enricher/internal/types"
	"github.com/nats-io/nats.go"
)

func main() {
	cfg := config.Load("fetcher")

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
		var input types.IncidentInput
		if err := mem.GetContextJSON(ctx, ctxPtr, &input); err != nil {
			return nil, err
		}
		maxBytes := policyconstraints.MaxArtifactBytes(req.Env)
		bundle, artifacts, err := incidents.MockEvidence(ctx, gw, input, maxBytes)
		if err != nil {
			return nil, err
		}
		resultPtr, err := mem.PutResultJSON(ctx, req.GetJobId(), bundle)
		if err != nil {
			return nil, err
		}
		return &agentv1.JobResult{
			JobId:        req.GetJobId(),
			Status:       agentv1.JobStatus_JOB_STATUS_SUCCEEDED,
			ResultPtr:    resultPtr,
			WorkerId:     cfg.WorkerID,
			ExecutionMs:  time.Since(start).Milliseconds(),
			ArtifactPtrs: artifacts,
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

	log.Printf("fetcher listening on %s for job.incident-enricher.fetch (worker_id=%s pool=%s)", subject, cfg.WorkerID, cfg.WorkerPool)
	<-ctx.Done()
}
