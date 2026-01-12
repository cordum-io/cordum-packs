package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cordum-io/cordum-packs/packs/mcp-bridge/internal/bridge"
	"github.com/cordum-io/cordum-packs/packs/mcp-bridge/internal/mcp"
)

func main() {
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	b, err := bridge.New(cfg)
	if err != nil {
		log.Fatalf("bridge init failed: %v", err)
	}
	defer b.Close()

	go func() {
		if err := b.RunWorker(ctx); err != nil {
			log.Printf("worker stopped: %v", err)
			stop()
		}
	}()

	server := mcp.NewServer(b, os.Stdin, os.Stdout)
	if err := server.Run(ctx); err != nil && !errorsIsCanceled(err) {
		log.Fatalf("mcp server stopped: %v", err)
	}
}

func loadConfig() bridge.Config {
	cfg := bridge.Config{
		GatewayURL:    envOr("CORDUM_GATEWAY_URL", "http://localhost:8081"),
		APIKey:        envOr("CORDUM_API_KEY", ""),
		NatsURL:       envOr("CORDUM_NATS_URL", "nats://localhost:4222"),
		RedisURL:      envOr("CORDUM_REDIS_URL", "redis://localhost:6379"),
		Pool:          envOr("CORDUM_MCP_POOL", "mcp-bridge"),
		Queue:         envOr("CORDUM_MCP_QUEUE", "mcp-bridge"),
		JobTopic:      envOr("CORDUM_MCP_JOB_TOPIC", "job.mcp-bridge.tool"),
		PackID:        envOr("CORDUM_MCP_PACK_ID", "mcp-bridge"),
		ServerName:    envOr("CORDUM_MCP_SERVER_NAME", "cordum-mcp-bridge"),
		ServerVersion: envOr("CORDUM_MCP_SERVER_VERSION", "0.1.0"),
	}

	if raw := strings.TrimSpace(os.Getenv("CORDUM_MCP_SUBJECTS")); raw != "" {
		parts := strings.Split(raw, ",")
		for i, part := range parts {
			parts[i] = strings.TrimSpace(part)
		}
		cfg.Subjects = parts
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_MCP_CALL_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.CallTimeout = d
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_MCP_POLL_INTERVAL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.PollInterval = d
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CORDUM_MCP_MAX_PARALLEL")); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 32); err == nil {
			cfg.MaxParallel = int32(v)
		}
	}

	return cfg
}

func envOr(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func errorsIsCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}
