package bridge

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"
)

type ttlRedisBlobStore struct {
	client *redis.Client
	ttl    time.Duration
}

func newRedisBlobStoreWithTTL(redisURL string, ttl time.Duration) (runtime.BlobStore, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	return &ttlRedisBlobStore{client: client, ttl: ttl}, nil
}

func (s *ttlRedisBlobStore) Get(ctx context.Context, key string) ([]byte, error) {
	return s.client.Get(ctx, key).Bytes()
}

func (s *ttlRedisBlobStore) Set(ctx context.Context, key string, data []byte) error {
	expiration := time.Duration(0)
	if s.ttl > 0 {
		expiration = s.ttl
	}
	return s.client.Set(ctx, key, data, expiration).Err()
}

func (s *ttlRedisBlobStore) Close() error {
	return s.client.Close()
}

func resolveWorkerID(explicit, workerType string) string {
	workerID := strings.TrimSpace(explicit)
	if workerID == "" {
		workerID = strings.TrimSpace(os.Getenv("WORKER_ID"))
	}
	if workerID != "" {
		return workerID
	}
	workerType = strings.TrimSpace(workerType)
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		if workerType != "" {
			return workerType
		}
		return "cordum-worker"
	}
	if workerType == "" {
		return host
	}
	return workerType + "-" + host
}
