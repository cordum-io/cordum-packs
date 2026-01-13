package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const pointerPrefix = "redis://"

type Store struct {
	client *redis.Client
	ttl    time.Duration
}

func New(redisURL string, ttl time.Duration) (*Store, error) {
	redisURL = strings.TrimSpace(redisURL)
	if redisURL == "" {
		return nil, errors.New("redis url is required")
	}
	var opts *redis.Options
	var err error
	if strings.Contains(redisURL, "://") {
		opts, err = redis.ParseURL(redisURL)
		if err != nil {
			return nil, fmt.Errorf("parse redis url: %w", err)
		}
	} else {
		opts = &redis.Options{Addr: redisURL}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Store{client: client, ttl: ttl}, nil
}

func (s *Store) Client() *redis.Client {
	return s.client
}

func (s *Store) GetContextJSON(ctx context.Context, ptr string, out any) error {
	data, err := s.GetByPointer(ctx, ptr)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unmarshal context: %w", err)
	}
	return nil
}

func (s *Store) PutResultJSON(ctx context.Context, jobID string, value any) (string, error) {
	if strings.TrimSpace(jobID) == "" {
		return "", errors.New("job id required")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal result: %w", err)
	}
	key := resultKey(jobID)
	if err := s.SetKey(ctx, key, data, s.ttl); err != nil {
		return "", err
	}
	return pointerForKey(key), nil
}

func (s *Store) GetByPointer(ctx context.Context, ptr string) ([]byte, error) {
	key, err := keyFromPointer(ptr)
	if err != nil {
		return nil, err
	}
	return s.GetKey(ctx, key)
}

func (s *Store) GetKey(ctx context.Context, key string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *Store) SetKey(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if ttl <= 0 {
		ttl = 0
	}
	if err := s.client.Set(ctx, key, value, ttl).Err(); err != nil {
		return err
	}
	return nil
}

func contextKey(jobID string) string {
	return "ctx:" + jobID
}

func resultKey(jobID string) string {
	return "res:" + jobID
}

func pointerForKey(key string) string {
	return pointerPrefix + key
}

func keyFromPointer(ptr string) (string, error) {
	ptr = strings.TrimSpace(ptr)
	if ptr == "" {
		return "", errors.New("empty pointer")
	}
	if !strings.HasPrefix(ptr, pointerPrefix) {
		return "", fmt.Errorf("invalid pointer prefix: %s", ptr)
	}
	key := strings.TrimPrefix(ptr, pointerPrefix)
	if key == "" {
		return "", errors.New("pointer missing key")
	}
	return key, nil
}

func ContextKey(jobID string) string {
	return contextKey(jobID)
}

func ResultKey(jobID string) string {
	return resultKey(jobID)
}

func PointerForKey(key string) string {
	return pointerForKey(key)
}
