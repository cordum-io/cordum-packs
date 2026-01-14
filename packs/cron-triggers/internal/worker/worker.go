package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path"
	"strings"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/client"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/cron-triggers/internal/config"
	"github.com/cordum-io/cordum-packs/packs/cron-triggers/internal/gatewayclient"
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
	gateway   *gatewayclient.Client
	redis     *redis.Client
	worker    *runtime.Worker
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

	worker, err := runtime.NewWorker(runtime.Config{
		Pool:            cfg.Pool,
		Subjects:        cfg.Subjects,
		Queue:           cfg.Queue,
		NatsURL:         cfg.NatsURL,
		MaxParallelJobs: cfg.MaxParallel,
		Capabilities:    []string{"cron-triggers"},
		Labels:          map[string]string{"adapter": "cron-triggers"},
		Type:            "cron-triggers",
	})
	if err != nil {
		return nil, err
	}

	store := scheduler.NewStore(redisClient)
	allowSeconds := false
	for _, profile := range cfg.Profiles {
		if profile.AllowSeconds {
			allowSeconds = true
			break
		}
	}

	sched := scheduler.New(
		store,
		client.New(cfg.GatewayURL, cfg.APIKey),
		cfg.Profiles,
		cfg.SyncInterval,
		cfg.LockTTL,
		cfg.SchedulerID,
		allowSeconds,
	)

	return &Worker{
		cfg:       cfg,
		gateway:   gatewayclient.New(cfg.GatewayURL, cfg.APIKey),
		redis:     redisClient,
		worker:    worker,
		store:     store,
		scheduler: sched,
	}, nil
}

func (w *Worker) Close() error {
	if w.worker != nil {
		_ = w.worker.Close()
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
	return w.worker.Run(ctx, w.handleJob)
}

func (w *Worker) handleJob(ctx context.Context, req *agentv1.JobRequest) (*agentv1.JobResult, error) {
	jobID := req.GetJobId()
	ctxPtr := req.GetContextPtr()
	if ctxPtr == "" && req.Env != nil {
		ctxPtr = req.Env["context_ptr"]
	}
	input, err := w.fetchInput(ctx, ctxPtr)
	if err != nil {
		return w.failJob(jobID, err)
	}

	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action == "" {
		return w.failJob(jobID, fmt.Errorf("action required"))
	}

	intent, err := classifyAction(action)
	if err != nil {
		return w.failJob(jobID, err)
	}
	if err := w.enforceTopic(req.GetTopic(), intent); err != nil {
		return w.failJob(jobID, err)
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return w.failJob(jobID, err)
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	start := time.Now()
	result, err := w.execute(ctx, profile, action, params)
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
	return w.finishJob(jobID, call, err)
}

func (w *Worker) execute(ctx context.Context, profile config.Profile, action string, params map[string]any) (any, error) {
	switch action {
	case actionSchedulesList:
		return w.listSchedules(ctx, profile)
	case actionSchedulesGet:
		return w.getSchedule(ctx, profile, params)
	case actionSchedulesCreate:
		return w.createSchedule(ctx, profile, params)
	case actionSchedulesUpdate:
		return w.updateSchedule(ctx, profile, params)
	case actionSchedulesDelete:
		return w.deleteSchedule(ctx, profile, params)
	case actionSchedulesEnable, actionSchedulesResume:
		return w.setScheduleEnabled(ctx, profile, params, true)
	case actionSchedulesDisable, actionSchedulesPause:
		return w.setScheduleEnabled(ctx, profile, params, false)
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
}

func (w *Worker) listSchedules(ctx context.Context, profile config.Profile) (any, error) {
	schedules, err := w.store.List(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]scheduler.Schedule, 0, len(schedules))
	for _, schedule := range schedules {
		if scheduleProfile(schedule) != profile.Name {
			continue
		}
		filtered = append(filtered, schedule)
	}
	return map[string]any{"schedules": filtered}, nil
}

func (w *Worker) getSchedule(ctx context.Context, profile config.Profile, params map[string]any) (any, error) {
	id := strings.TrimSpace(stringParam(params, "id"))
	if id == "" {
		return nil, fmt.Errorf("id required")
	}
	schedule, err := w.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if scheduleProfile(schedule) != profile.Name {
		return nil, fmt.Errorf("schedule not found")
	}
	return schedule, nil
}

func (w *Worker) createSchedule(ctx context.Context, profile config.Profile, params map[string]any) (any, error) {
	var payload scheduleParams
	if err := decodeParams(params, &payload); err != nil {
		return nil, err
	}
	workflowID := resolveWorkflowID(payload.WorkflowID, payload.Workflow)
	if workflowID == "" {
		return nil, fmt.Errorf("workflow_id required")
	}
	if !workflowAllowed(profile, workflowID) {
		return nil, fmt.Errorf("workflow not allowed: %s", workflowID)
	}
	cronSpec := strings.TrimSpace(payload.Cron)
	if cronSpec == "" {
		return nil, fmt.Errorf("cron required")
	}

	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	}

	timezone := strings.TrimSpace(payload.Timezone)
	if timezone == "" {
		timezone = profile.DefaultTimezone
	}

	schedule := scheduler.Schedule{
		ID:             strings.TrimSpace(payload.ID),
		Name:           strings.TrimSpace(payload.Name),
		Profile:        profile.Name,
		Cron:           cronSpec,
		WorkflowID:     workflowID,
		Input:          payload.Input,
		Enabled:        enabled,
		Timezone:       timezone,
		DryRun:         payload.DryRun,
		IdempotencyKey: strings.TrimSpace(payload.IdempotencyKey),
	}
	if _, err := w.scheduler.SpecFor(schedule, profile); err != nil {
		return nil, err
	}

	stored, err := w.store.Save(ctx, schedule)
	if err != nil {
		return nil, err
	}
	_ = w.scheduler.Sync(context.Background())
	return stored, nil
}

func (w *Worker) updateSchedule(ctx context.Context, profile config.Profile, params map[string]any) (any, error) {
	var payload scheduleParams
	if err := decodeParams(params, &payload); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(payload.ID)
	if id == "" {
		return nil, fmt.Errorf("id required")
	}

	schedule, err := w.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if scheduleProfile(schedule) != profile.Name {
		return nil, fmt.Errorf("schedule not found")
	}

	if strings.TrimSpace(payload.Name) != "" {
		schedule.Name = strings.TrimSpace(payload.Name)
	}
	if strings.TrimSpace(payload.Cron) != "" {
		schedule.Cron = strings.TrimSpace(payload.Cron)
	}
	workflowID := resolveWorkflowID(payload.WorkflowID, payload.Workflow)
	if workflowID != "" {
		if !workflowAllowed(profile, workflowID) {
			return nil, fmt.Errorf("workflow not allowed: %s", workflowID)
		}
		schedule.WorkflowID = workflowID
	}
	if paramExists(params, "input") {
		schedule.Input = payload.Input
	}
	if payload.Enabled != nil {
		schedule.Enabled = *payload.Enabled
	}
	if paramExists(params, "dry_run") {
		schedule.DryRun = payload.DryRun
	}
	if strings.TrimSpace(payload.Timezone) != "" {
		schedule.Timezone = strings.TrimSpace(payload.Timezone)
	}
	if strings.TrimSpace(payload.IdempotencyKey) != "" {
		schedule.IdempotencyKey = strings.TrimSpace(payload.IdempotencyKey)
	}
	if _, err := w.scheduler.SpecFor(schedule, profile); err != nil {
		return nil, err
	}

	stored, err := w.store.Save(ctx, schedule)
	if err != nil {
		return nil, err
	}
	_ = w.scheduler.Sync(context.Background())
	return stored, nil
}

func (w *Worker) deleteSchedule(ctx context.Context, profile config.Profile, params map[string]any) (any, error) {
	id := strings.TrimSpace(stringParam(params, "id"))
	if id == "" {
		return nil, fmt.Errorf("id required")
	}
	schedule, err := w.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if scheduleProfile(schedule) != profile.Name {
		return nil, fmt.Errorf("schedule not found")
	}
	if err := w.store.Delete(ctx, id); err != nil {
		return nil, err
	}
	_ = w.scheduler.Sync(context.Background())
	return map[string]any{"deleted": id}, nil
}

func (w *Worker) setScheduleEnabled(ctx context.Context, profile config.Profile, params map[string]any, enabled bool) (any, error) {
	id := strings.TrimSpace(stringParam(params, "id"))
	if id == "" {
		return nil, fmt.Errorf("id required")
	}
	schedule, err := w.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if scheduleProfile(schedule) != profile.Name {
		return nil, fmt.Errorf("schedule not found")
	}
	schedule.Enabled = enabled
	stored, err := w.store.Save(ctx, schedule)
	if err != nil {
		return nil, err
	}
	_ = w.scheduler.Sync(context.Background())
	return stored, nil
}

func (w *Worker) fetchInput(ctx context.Context, ptr string) (JobInput, error) {
	if strings.TrimSpace(ptr) == "" {
		return JobInput{}, fmt.Errorf("context_ptr missing")
	}
	mem, err := w.gateway.GetMemory(ctx, ptr)
	if err != nil {
		return JobInput{}, err
	}
	payload, ok := mem.JSON.(map[string]any)
	if !ok {
		return JobInput{}, fmt.Errorf("unexpected context format")
	}
	if ctxPayload, ok := payload["context"].(map[string]any); ok {
		payload = ctxPayload
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return JobInput{}, err
	}
	var input JobInput
	if err := json.Unmarshal(data, &input); err != nil {
		return JobInput{}, err
	}
	return input, nil
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

func (w *Worker) finishJob(jobID string, result callResult, err error) (*agentv1.JobResult, error) {
	ptr, storeErr := w.storeResult(context.Background(), jobID, result)
	if storeErr != nil {
		return &agentv1.JobResult{JobId: jobID, Status: agentv1.JobStatus_JOB_STATUS_FAILED, ErrorMessage: storeErr.Error()}, storeErr
	}
	status := agentv1.JobStatus_JOB_STATUS_SUCCEEDED
	if err != nil {
		status = agentv1.JobStatus_JOB_STATUS_FAILED
	}
	return &agentv1.JobResult{JobId: jobID, Status: status, ResultPtr: ptr}, err
}

func (w *Worker) failJob(jobID string, err error) (*agentv1.JobResult, error) {
	return &agentv1.JobResult{JobId: jobID, Status: agentv1.JobStatus_JOB_STATUS_FAILED, ErrorMessage: err.Error()}, err
}

func (w *Worker) storeResult(ctx context.Context, jobID string, payload any) (string, error) {
	if w.redis == nil {
		return "", fmt.Errorf("redis client unavailable")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	key := "res:" + jobID
	if err := w.redis.Set(ctx, key, data, w.cfg.ResultTTL).Err(); err != nil {
		return "", err
	}
	return "redis://" + key, nil
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
