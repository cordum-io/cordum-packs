package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	scheduleSetKey    = "cron:schedules"
	scheduleKeyPrefix = "cron:schedule:"
	lockKeyPrefix     = "cron:lock:"
)

var ErrScheduleNotFound = errors.New("schedule not found")

type Store struct {
	redis *redis.Client
}

func NewStore(redisClient *redis.Client) *Store {
	return &Store{redis: redisClient}
}

type Schedule struct {
	ID             string         `json:"id"`
	Name           string         `json:"name,omitempty"`
	Profile        string         `json:"profile,omitempty"`
	Cron           string         `json:"cron"`
	WorkflowID     string         `json:"workflow_id"`
	Input          map[string]any `json:"input,omitempty"`
	Enabled        bool           `json:"enabled"`
	Timezone       string         `json:"timezone,omitempty"`
	DryRun         bool           `json:"dry_run,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	CreatedAt      string         `json:"created_at,omitempty"`
	UpdatedAt      string         `json:"updated_at,omitempty"`
	LastRunAt      string         `json:"last_run_at,omitempty"`
	NextRunAt      string         `json:"next_run_at,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
}

func (s *Store) Save(ctx context.Context, schedule Schedule) (Schedule, error) {
	if schedule.ID == "" {
		schedule.ID = uuid.NewString()
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if schedule.CreatedAt == "" {
		schedule.CreatedAt = now
	}
	schedule.UpdatedAt = now

	data, err := json.Marshal(schedule)
	if err != nil {
		return Schedule{}, err
	}
	key := scheduleKeyPrefix + schedule.ID
	pipe := s.redis.TxPipeline()
	pipe.Set(ctx, key, data, 0)
	pipe.SAdd(ctx, scheduleSetKey, schedule.ID)
	if _, err := pipe.Exec(ctx); err != nil {
		return Schedule{}, err
	}
	return schedule, nil
}

func (s *Store) Get(ctx context.Context, id string) (Schedule, error) {
	if id == "" {
		return Schedule{}, ErrScheduleNotFound
	}
	key := scheduleKeyPrefix + id
	data, err := s.redis.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return Schedule{}, ErrScheduleNotFound
		}
		return Schedule{}, err
	}
	var schedule Schedule
	if err := json.Unmarshal(data, &schedule); err != nil {
		return Schedule{}, err
	}
	return schedule, nil
}

func (s *Store) List(ctx context.Context) ([]Schedule, error) {
	ids, err := s.redis.SMembers(ctx, scheduleSetKey).Result()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	pipe := s.redis.Pipeline()
	cmds := make([]*redis.StringCmd, 0, len(ids))
	for _, id := range ids {
		cmds = append(cmds, pipe.Get(ctx, scheduleKeyPrefix+id))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	out := make([]Schedule, 0, len(cmds))
	for _, cmd := range cmds {
		data, err := cmd.Bytes()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, err
		}
		var schedule Schedule
		if err := json.Unmarshal(data, &schedule); err != nil {
			return nil, err
		}
		out = append(out, schedule)
	}
	return out, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	if id == "" {
		return ErrScheduleNotFound
	}
	key := scheduleKeyPrefix + id
	pipe := s.redis.TxPipeline()
	pipe.Del(ctx, key)
	pipe.SRem(ctx, scheduleSetKey, id)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *Store) SetRunMetadata(ctx context.Context, id string, lastRun time.Time, nextRun time.Time, lastError string) error {
	schedule, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if !lastRun.IsZero() {
		schedule.LastRunAt = lastRun.UTC().Format(time.RFC3339)
	}
	if !nextRun.IsZero() {
		schedule.NextRunAt = nextRun.UTC().Format(time.RFC3339)
	}
	schedule.LastError = lastError
	_, err = s.Save(ctx, schedule)
	return err
}

func (s *Store) AcquireRunLock(ctx context.Context, scheduleID string, tick time.Time, ttl time.Duration, owner string) (bool, error) {
	if scheduleID == "" {
		return false, fmt.Errorf("schedule id required")
	}
	key := fmt.Sprintf("%s%s:%d", lockKeyPrefix, scheduleID, tick.UTC().Unix())
	return s.redis.SetNX(ctx, key, owner, ttl).Result()
}
