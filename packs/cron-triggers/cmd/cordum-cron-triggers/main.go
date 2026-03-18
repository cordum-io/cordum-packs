package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cordum/cordum/sdk/logging"

	"github.com/cordum-io/cordum-packs/packs/cron-triggers/internal/config"
	"github.com/cordum-io/cordum-packs/packs/cron-triggers/internal/worker"
)

func main() {
	logging.Init("cron-triggers")

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	w, err := worker.New(cfg)
	if err != nil {
		slog.Error("worker init failed", "error", err)
		os.Exit(1)
	}
	defer w.Close()

	if err := w.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("worker stopped", "error", err)
		os.Exit(1)
	}
}
