package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/config"
	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/server"
	"github.com/cordum/cordum/sdk/logging"
)

func main() {
	logging.Init("webhooks")
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	client := gatewayclient.New(cfg.GatewayURL, cfg.APIKey, cfg.TenantID)
	srv := server.New(cfg, client)

	httpServer := &http.Server{
		Addr:              cfg.BindAddress,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	slog.Info("cordum-webhooks listening", "address", cfg.BindAddress)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
