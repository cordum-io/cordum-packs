package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cordum-io/cordum-packs/packs/pic-standard/internal/config"
	"github.com/cordum-io/cordum-packs/packs/pic-standard/internal/picclient"
	"github.com/cordum-io/cordum-packs/packs/pic-standard/internal/worker"
	"github.com/cordum/cordum/sdk/logging"
)

func main() {
	logger := logging.Init("pic-standard")

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	// Startup health check (warn only, don't crash)
	pic := picclient.New(cfg.BridgeURL, cfg.BridgeTimeout, cfg.BridgeToken)
	if err := pic.HealthCheck(context.Background()); err != nil {
		logger.Warn("PIC bridge not reachable at startup", "bridge_url", cfg.BridgeURL, "error", err)
	} else {
		logger.Info("PIC bridge healthy", "bridge_url", cfg.BridgeURL)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	w, err := worker.New(cfg, logger)
	if err != nil {
		logger.Error("worker init failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := w.Close(); err != nil {
			logger.Warn("worker close failed", "error", err)
		}
	}()

	if err := w.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("worker stopped", "error", err)
		os.Exit(1)
	}
}
