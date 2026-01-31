package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/client"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/cron-triggers/internal/config"
	"github.com/cordum-io/cordum-packs/packs/cron-triggers/internal/scheduler"
)

const (
	topicRead  = "job.cron-triggers.read"
	topicWrite = "job.cron-triggers.write"
)

const (
	actionSchedulesList    = "schedules.list"
	actionSchedulesGet     = "schedules.get"
	actionSchedulesCreate  = "schedules.create"
	actionSchedulesUpdate  = "schedules.update"
	actionSchedulesDelete  = "schedules.delete"
	actionSchedulesEnable  = "schedules.enable"
	actionSchedulesDisable = "schedules.disable"
	actionSchedulesPause   = "schedules.pause"
	actionSchedulesResume  = "schedules.resume"
)

type Worker struct {
	cfg       config.Config
	redis     *redis.Client
	agent     *runtime.Agent
	natsConn  *nats.Conn
	workerID  string
	sem       chan struct{}
	active    int32
	store     *scheduler.Store
	scheduler *scheduler.Scheduler
}

type JobInput struct {
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
}

type callResult struct {
	JobID      string `json:"job_id"`
	Profile    string `json:"profile"`
	Action     string `json:"action"`
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.GatewayURL == "" {
		return nil, fmt.Errorf("gateway url required")
	}
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	redisClient := redis.NewClient(opts)

	workerID := resolveWorkerID("", "cron-triggers")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	resultStore, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		return nil, err
	}
	agent := &runtime.Agent{
		NATS:     nc,
		Store:    resultStore,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	schedStore := scheduler.NewStore(redisClient)
	allowSeconds := false
	for _, profile := range cfg.Profiles {
		if profile.AllowSeconds {
			allowSeconds = true
			break
		}
	}

	sched := scheduler.New(
		schedStore,
		client.New(cfg.GatewayURL, cfg.APIKey),
		cfg.Profiles,
		cfg.SyncInterval,
		cfg.LockTTL,
		cfg.SchedulerID,
		allowSeconds,
	)

	w := &Worker{
		cfg:       cfg,
		redis:     redisClient,
		agent:     agent,
		natsConn:  nc,
		workerID:  workerID,
		store:     schedStore,
		scheduler: sched,
	}
	if cfg.MaxParallel > 0 {
		w.sem = make(chan struct{}, cfg.MaxParallel)
	}
	return w, nil
}

func (w *Worker) Close() error {
	if w.agent != nil {
		_ = w.agent.Close()
	}
	if w.redis != nil {
		_ = w.redis.Close()
	}
	return nil
}

func (w *Worker) Run(ctx context.Context) error {
	go func() {
		if err := w.scheduler.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("cron scheduler stopped: %v", err)
		}
	}()
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}
	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{topicRead, topicWrite}
	}
	for _, subject := range subjects {
		runtime.Register(w.agent, subject, w.handleJob)
	}
	runtime.Register(w.agent, runtime.DirectSubject(w.workerID), w.handleJob)

	if err := w.agent.Start(); err != nil {
		return err
	}
	if w.natsConn != nil {
		heartbeatFn := func() ([]byte, error) {
			active := int(atomic.LoadInt32(&w.active))
			return runtime.HeartbeatPayload(w.workerID, w.cfg.Pool, active, int(w.cfg.MaxParallel), 0)
		}
		if payload, err := heartbeatFn(); err == nil {
			_ = runtime.EmitHeartbeat(w.natsConn, payload)
		}
		go runtime.HeartbeatLoop(ctx, w.natsConn, heartbeatFn)
	}

	<-ctx.Done()
	return ctx.Err()
}

func (w *Worker) handleJob(ctx runtime.Context, payload map[string]any) (callResult, error) {
	if w.sem != nil {
		w.sem <- struct{}{}
		atomic.AddInt32(&w.active, 1)
		defer func() {
			<-w.sem
			atomic.AddInt32(&w.active, -1)
		}()
	} else {
		atomic.AddInt32(&w.active, 1)
		defer atomic.AddInt32(&w.active, -1)
	}

	jobID := ctx.Job.GetJobId()
	payload = normalizePayload(payload)

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		return callResult{}, err
	}

	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action == "" {
		return callResult{}, fmt.Errorf("action required")
	}

	intent, err := classifyAction(action)
	if err != nil {
		return callResult{}, err
	}
	if err := w.enforceTopic(ctx.Job.GetTopic(), intent); err != nil {
		return callResult{}, err
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return callResult{}, err
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	start := time.Now()
	result, err := w.execute(context.Background(), profile, action, params)
	statusCode := 200
	if err != nil {
		statusCode = 400
	}

	call := callResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     action,
		StatusCode: statusCode,
		RequestID:  strings.TrimSpace(input.RequestID),
		DurationMs: time.Since(start).Milliseconds(),
		Result:     result,
	}
	if err != nil {
		call.Error = err.Error()
	}
	return call, err
}

func (w *Worker) execute(ctx context.Context, profile config.Profile, action string, params map[string]any) (any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := w.cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch action {
	case actionSchedulesList:
		schedules, err := w.store.List(reqCtx)
		if err != nil {
			return nil, err
		}
		out := make([]scheduler.Schedule, 0, len(schedules))
		for _, schedule := range schedules {
			if scheduleProfile(schedule) == profile.Name {
				out = append(out, schedule)
			}
		}
		return out, nil
	case actionSchedulesGet:
		var payload scheduleParams
		if err := decodeParams(params, &payload); err != nil {
			return nil, err
		}
		id := strings.TrimSpace(payload.ID)
		if id == "" {
			return nil, fmt.Errorf("id required")
		}
		schedule, err := w.store.Get(reqCtx, id)
		if err != nil {
			return nil, err
		}
		if scheduleProfile(schedule) != profile.Name {
			return nil, scheduler.ErrScheduleNotFound
		}
		return schedule, nil
	case actionSchedulesCreate:
		var payload scheduleParams
		if err := decodeParams(params, &payload); err != nil {
			return nil, err
		}
		workflowID := resolveWorkflowID(payload.WorkflowID, payload.Workflow)
		if workflowID == "" {
			return nil, fmt.Errorf("workflow_id required")
		}
		if !workflowAllowed(profile, workflowID) {
			return nil, fmt.Errorf("workflow not allowed")
		}
		cronExpr := strings.TrimSpace(payload.Cron)
		if cronExpr == "" {
			return nil, fmt.Errorf("cron required")
		}
		enabled := true
		if payload.Enabled != nil {
			enabled = *payload.Enabled
		}
		schedule := scheduler.Schedule{
			ID:             strings.TrimSpace(payload.ID),
			Name:           strings.TrimSpace(payload.Name),
			Profile:        profile.Name,
			Cron:           cronExpr,
			WorkflowID:     workflowID,
			Input:          payload.Input,
			Enabled:        enabled,
			Timezone:       strings.TrimSpace(payload.Timezone),
			DryRun:         payload.DryRun,
			IdempotencyKey: strings.TrimSpace(payload.IdempotencyKey),
		}
		if _, err := w.scheduler.SpecFor(schedule, profile); err != nil {
			return nil, err
		}
		if schedule.ID != "" {
			if _, err := w.store.Get(reqCtx, schedule.ID); err == nil {
				return nil, fmt.Errorf("schedule already exists")
			} else if !errors.Is(err, scheduler.ErrScheduleNotFound) {
				return nil, err
			}
		}
		saved, err := w.store.Save(reqCtx, schedule)
		if err != nil {
			return nil, err
		}
		if err := w.scheduler.Sync(reqCtx); err != nil {
			log.Printf("cron scheduler sync failed: %v", err)
		}
		return saved, nil
	case actionSchedulesUpdate:
		var payload scheduleParams
		if err := decodeParams(params, &payload); err != nil {
			return nil, err
		}
		id := strings.TrimSpace(payload.ID)
		if id == "" {
			return nil, fmt.Errorf("id required")
		}
		schedule, err := w.store.Get(reqCtx, id)
		if err != nil {
			return nil, err
		}
		if scheduleProfile(schedule) != profile.Name {
			return nil, scheduler.ErrScheduleNotFound
		}
		if paramExists(params, "name") {
			schedule.Name = strings.TrimSpace(payload.Name)
		}
		if paramExists(params, "cron") {
			schedule.Cron = strings.TrimSpace(payload.Cron)
		}
		if paramExists(params, "workflow_id") || paramExists(params, "workflow") {
			workflowID := resolveWorkflowID(payload.WorkflowID, payload.Workflow)
			if workflowID == "" {
				return nil, fmt.Errorf("workflow_id required")
			}
			schedule.WorkflowID = workflowID
		}
		if paramExists(params, "input") {
			schedule.Input = payload.Input
		}
		if paramExists(params, "enabled") {
			if payload.Enabled == nil {
				return nil, fmt.Errorf("enabled must be boolean")
			}
			schedule.Enabled = *payload.Enabled
		}
		if paramExists(params, "timezone") {
			schedule.Timezone = strings.TrimSpace(payload.Timezone)
		}
		if paramExists(params, "dry_run") {
			schedule.DryRun = payload.DryRun
		}
		if paramExists(params, "idempotency_key") {
			schedule.IdempotencyKey = strings.TrimSpace(payload.IdempotencyKey)
		}
		if !workflowAllowed(profile, schedule.WorkflowID) {
			return nil, fmt.Errorf("workflow not allowed")
		}
		if _, err := w.scheduler.SpecFor(schedule, profile); err != nil {
			return nil, err
		}
		saved, err := w.store.Save(reqCtx, schedule)
		if err != nil {
			return nil, err
		}
		if err := w.scheduler.Sync(reqCtx); err != nil {
			log.Printf("cron scheduler sync failed: %v", err)
		}
		return saved, nil
	case actionSchedulesDelete:
		var payload scheduleParams
		if err := decodeParams(params, &payload); err != nil {
			return nil, err
		}
		id := strings.TrimSpace(payload.ID)
		if id == "" {
			return nil, fmt.Errorf("id required")
		}
		schedule, err := w.store.Get(reqCtx, id)
		if err != nil {
			return nil, err
		}
		if scheduleProfile(schedule) != profile.Name {
			return nil, scheduler.ErrScheduleNotFound
		}
		if err := w.store.Delete(reqCtx, id); err != nil {
			return nil, err
		}
		if err := w.scheduler.Sync(reqCtx); err != nil {
			log.Printf("cron scheduler sync failed: %v", err)
		}
		return map[string]any{"deleted": true, "id": id}, nil
	case actionSchedulesEnable, actionSchedulesDisable, actionSchedulesPause, actionSchedulesResume:
		var payload scheduleParams
		if err := decodeParams(params, &payload); err != nil {
			return nil, err
		}
		id := strings.TrimSpace(payload.ID)
		if id == "" {
			return nil, fmt.Errorf("id required")
		}
		schedule, err := w.store.Get(reqCtx, id)
		if err != nil {
			return nil, err
		}
		if scheduleProfile(schedule) != profile.Name {
			return nil, scheduler.ErrScheduleNotFound
		}
		switch action {
		case actionSchedulesEnable, actionSchedulesResume:
			schedule.Enabled = true
		default:
			schedule.Enabled = false
		}
		saved, err := w.store.Save(reqCtx, schedule)
		if err != nil {
			return nil, err
		}
		if err := w.scheduler.Sync(reqCtx); err != nil {
			log.Printf("cron scheduler sync failed: %v", err)
		}
		return saved, nil
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
}

func normalizePayload(payload map[string]any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	if ctxPayload, ok := payload["context"].(map[string]any); ok {
		return ctxPayload
	}
	return payload
}

func decodePayload(payload map[string]any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (w *Worker) resolveProfile(name string) (config.Profile, error) {
	profileName := strings.TrimSpace(name)
	if profileName == "" {
		profileName = w.cfg.DefaultProfile
	}
	if profileName == "" {
		return config.Profile{}, fmt.Errorf("profile required")
	}
	profile, ok := w.cfg.Profiles[profileName]
	if !ok {
		return config.Profile{}, fmt.Errorf("unknown profile: %s", profileName)
	}
	if profile.Name == "" {
		profile.Name = profileName
	}
	return profile, nil
}

func (w *Worker) enforceTopic(topic string, intent string) error {
	switch intent {
	case "read":
		if topic != topicRead {
			return fmt.Errorf("read actions require %s topic", topicRead)
		}
	case "write":
		if topic != topicWrite {
			return fmt.Errorf("write actions require %s topic", topicWrite)
		}
	default:
		return fmt.Errorf("unknown intent")
	}
	return nil
}

func classifyAction(action string) (string, error) {
	switch action {
	case actionSchedulesList, actionSchedulesGet:
		return "read", nil
	case actionSchedulesCreate, actionSchedulesUpdate, actionSchedulesDelete, actionSchedulesEnable, actionSchedulesDisable, actionSchedulesPause, actionSchedulesResume:
		return "write", nil
	default:
		return "", fmt.Errorf("unsupported action: %s", action)
	}
}

type scheduleParams struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Cron           string         `json:"cron"`
	WorkflowID     string         `json:"workflow_id"`
	Workflow       string         `json:"workflow"`
	Input          map[string]any `json:"input"`
	Enabled        *bool          `json:"enabled"`
	Timezone       string         `json:"timezone"`
	DryRun         bool           `json:"dry_run"`
	IdempotencyKey string         `json:"idempotency_key"`
}

func resolveWorkflowID(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	return strings.TrimSpace(fallback)
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

func decodeParams(params map[string]any, out any) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func paramExists(params map[string]any, key string) bool {
	_, ok := params[key]
	return ok
}

func stringParam(params map[string]any, key string) string {
	if val, ok := params[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func scheduleProfile(schedule scheduler.Schedule) string {
	name := strings.TrimSpace(schedule.Profile)
	if name == "" {
		return "default"
	}
	return name
}
