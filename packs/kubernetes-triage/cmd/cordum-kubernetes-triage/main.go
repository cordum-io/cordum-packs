package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cordum-io/cordum-packs/packs/kubernetes-triage/internal/config"
	"github.com/cordum-io/cordum-packs/packs/kubernetes-triage/internal/worker"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	w, err := worker.New(cfg)
	if err != nil {
		log.Fatalf("worker init failed: %v", err)
	}
	defer w.Close()

	if err := w.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("worker stopped: %v", err)
	}
}
