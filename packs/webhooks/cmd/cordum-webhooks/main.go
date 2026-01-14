package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/config"
	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/gatewayclient"
	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	client := gatewayclient.New(cfg.GatewayURL, cfg.APIKey)
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

	log.Printf("cordum-webhooks listening on %s", cfg.BindAddress)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server stopped: %v", err)
	}
}
