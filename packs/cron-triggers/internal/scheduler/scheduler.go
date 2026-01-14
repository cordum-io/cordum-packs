package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cordum/cordum/sdk/client"
	"github.com/robfig/cron/v3"

	"github.com/cordum-io/cordum-packs/packs/cron-triggers/internal/config"
)

type Scheduler struct {
	store        *Store
	gateway      *client.Client
	profiles     map[string]config.Profile
	cron         *cron.Cron
	parser       cron.Parser
	syncInterval time.Duration
	lockTTL      time.Duration
	schedulerID  string

	mu      sync.Mutex
	entries map[string]entryState
	logger  *log.Logger
}

type entryState struct {
	entryID cron.EntryID
	hash    string
}

func New(store *Store, gateway *client.Client, profiles map[string]config.Profile, syncInterval time.Duration, lockTTL time.Duration, schedulerID string, allowSeconds bool) *Scheduler {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	if allowSeconds {
		parser = cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	}
	return &Scheduler{
		store:        store,
		gateway:      gateway,
		profiles:     profiles,
		cron:         cron.New(cron.WithParser(parser)),
		parser:       parser,
		syncInterval: syncInterval,
		lockTTL:      lockTTL,
		schedulerID:  schedulerID,
		entries:      map[string]entryState{},
		logger:       log.Default(),
	}
}

func (s *Scheduler) Run(ctx context.Context) error {
	if err := s.Sync(ctx); err != nil {
		s.logger.Printf("cron scheduler initial sync failed: %v", err)
	}
	s.cron.Start()
	defer s.cron.Stop()

	ticker := time.NewTicker(s.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.Sync(ctx); err != nil {
				s.logger.Printf("cron scheduler sync failed: %v", err)
			}
		}
	}
}

func (s *Scheduler) SpecFor(schedule Schedule, profile config.Profile) (string, error) {
	return s.buildSpec(schedule, profile)
}

func (s *Scheduler) Sync(ctx context.Context) error {
	schedules, err := s.store.List(ctx)
	if err != nil {
		return err
	}

	seen := map[string]struct{}{}
	for _, schedule := range schedules {
		seen[schedule.ID] = struct{}{}
		hash := scheduleHash(schedule)
		s.mu.Lock()
		state, exists := s.entries[schedule.ID]
		s.mu.Unlock()

		if schedule.Enabled {
			if !exists || state.hash != hash {
				if exists {
					s.removeEntry(schedule.ID)
				}
				if err := s.addEntry(ctx, schedule); err != nil {
					s.logger.Printf("cron scheduler: add schedule failed (%s): %v", schedule.ID, err)
					continue
				}
			}
		} else if exists {
			s.removeEntry(schedule.ID)
		}
	}

	s.mu.Lock()
	for id := range s.entries {
		if _, ok := seen[id]; !ok {
			s.cron.Remove(s.entries[id].entryID)
			delete(s.entries, id)
		}
	}
	s.mu.Unlock()

	return nil
}

func (s *Scheduler) addEntry(ctx context.Context, schedule Schedule) error {
	profile := s.profileForSchedule(schedule)
	if profile.Name == "" {
		return fmt.Errorf("unknown profile for schedule: %s", schedule.Profile)
	}

	spec, err := s.buildSpec(schedule, profile)
	if err != nil {
		return err
	}

	entryID, err := s.cron.AddFunc(spec, func() {
		s.trigger(schedule.ID)
	})
	if err != nil {
		return err
	}

	nextRun, err := s.nextRunAt(spec)
	if err == nil {
		_ = s.store.SetRunMetadata(ctx, schedule.ID, time.Time{}, nextRun, "")
	}

	s.mu.Lock()
	s.entries[schedule.ID] = entryState{entryID: entryID, hash: scheduleHash(schedule)}
	s.mu.Unlock()
	return nil
}

func (s *Scheduler) removeEntry(scheduleID string) {
	s.mu.Lock()
	state, ok := s.entries[scheduleID]
	if ok {
		s.cron.Remove(state.entryID)
		delete(s.entries, scheduleID)
	}
	s.mu.Unlock()
}

func (s *Scheduler) trigger(scheduleID string) {
	ctx := context.Background()
	schedule, err := s.store.Get(ctx, scheduleID)
	if err != nil {
		s.logger.Printf("cron scheduler: schedule missing (%s): %v", scheduleID, err)
		return
	}
	if !schedule.Enabled {
		return
	}
	profile := s.profileForSchedule(schedule)
	if profile.Name == "" {
		s.logger.Printf("cron scheduler: schedule profile missing (%s)", scheduleID)
		return
	}
	if !workflowAllowed(profile, schedule.WorkflowID) {
		s.logger.Printf("cron scheduler: workflow not allowed (%s)", schedule.WorkflowID)
		return
	}

	now := time.Now().UTC()
	locked, err := s.store.AcquireRunLock(ctx, scheduleID, now, s.lockTTL, s.schedulerID)
	if err != nil {
		s.logger.Printf("cron scheduler: lock failed (%s): %v", scheduleID, err)
		return
	}
	if !locked {
		return
	}

	idempotencyKey := schedule.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = schedule.ID
	}
	idempotencyKey = fmt.Sprintf("%s:%s", idempotencyKey, now.Format(time.RFC3339))

	_, err = s.gateway.StartRunWithOptions(ctx, schedule.WorkflowID, schedule.Input, client.RunOptions{
		DryRun:         schedule.DryRun,
		IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		_ = s.store.SetRunMetadata(ctx, scheduleID, now, time.Time{}, err.Error())
		s.logger.Printf("cron scheduler: run failed (%s): %v", scheduleID, err)
		return
	}

	spec, err := s.buildSpec(schedule, profile)
	if err != nil {
		_ = s.store.SetRunMetadata(ctx, scheduleID, now, time.Time{}, "")
		return
	}
	nextRun, err := s.nextRunAt(spec)
	if err != nil {
		_ = s.store.SetRunMetadata(ctx, scheduleID, now, time.Time{}, "")
		return
	}
	_ = s.store.SetRunMetadata(ctx, scheduleID, now, nextRun, "")
}

func (s *Scheduler) buildSpec(schedule Schedule, profile config.Profile) (string, error) {
	spec := strings.TrimSpace(schedule.Cron)
	if spec == "" {
		return "", fmt.Errorf("cron expression required")
	}
	if !profile.AllowSeconds && hasSecondsField(spec) {
		return "", fmt.Errorf("cron seconds not allowed for profile %s", profile.Name)
	}

	tz := strings.TrimSpace(schedule.Timezone)
	if tz == "" {
		tz = strings.TrimSpace(profile.DefaultTimezone)
	}
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return "", fmt.Errorf("invalid timezone: %s", tz)
	}
	if !hasTimezonePrefix(spec) {
		spec = "CRON_TZ=" + tz + " " + spec
	}
	return spec, nil
}

func (s *Scheduler) nextRunAt(spec string) (time.Time, error) {
	sched, err := s.parser.Parse(spec)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(time.Now().UTC()), nil
}

func (s *Scheduler) profileForSchedule(schedule Schedule) config.Profile {
	name := strings.TrimSpace(schedule.Profile)
	if name == "" {
		name = "default"
	}
	profile, ok := s.profiles[name]
	if !ok {
		return config.Profile{}
	}
	if profile.Name == "" {
		profile.Name = name
	}
	return profile
}

func scheduleHash(schedule Schedule) string {
	payload := map[string]any{
		"cron":            schedule.Cron,
		"workflow_id":     schedule.WorkflowID,
		"input":           schedule.Input,
		"enabled":         schedule.Enabled,
		"timezone":        schedule.Timezone,
		"dry_run":         schedule.DryRun,
		"idempotency_key": schedule.IdempotencyKey,
		"profile":         schedule.Profile,
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func workflowAllowed(profile config.Profile, workflowID string) bool {
	if workflowID == "" {
		return false
	}
	if len(profile.AllowedWorkflows) > 0 && !matchAny(profile.AllowedWorkflows, workflowID) {
		return false
	}
	if matchAny(profile.DeniedWorkflows, workflowID) {
		return false
	}
	return true
}

func matchAny(patterns []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, pattern := range patterns {
		candidate := strings.ToLower(strings.TrimSpace(pattern))
		if candidate == "" {
			continue
		}
		if candidate == value {
			return true
		}
		if ok, _ := path.Match(candidate, value); ok {
			return true
		}
	}
	return false
}

func hasTimezonePrefix(spec string) bool {
	upper := strings.ToUpper(strings.TrimSpace(spec))
	return strings.HasPrefix(upper, "CRON_TZ=") || strings.HasPrefix(upper, "TZ=")
}

func hasSecondsField(spec string) bool {
	fields := strings.Fields(spec)
	if len(fields) == 0 {
		return false
	}
	if strings.HasPrefix(strings.ToUpper(fields[0]), "CRON_TZ=") || strings.HasPrefix(strings.ToUpper(fields[0]), "TZ=") {
		fields = fields[1:]
	}
	return len(fields) == 6
}
