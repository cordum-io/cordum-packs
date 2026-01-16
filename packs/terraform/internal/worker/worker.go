package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/redis/go-redis/v9"

	"github.com/cordum-io/cordum-packs/packs/terraform/internal/config"
	"github.com/cordum-io/cordum-packs/packs/terraform/internal/gatewayclient"
)

type Worker struct {
	cfg     config.Config
	gateway *gatewayclient.Client
	redis   *redis.Client
	worker  *runtime.Worker
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
	Dir        string `json:"dir,omitempty"`
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

type actionSpec struct {
	Name   string
	Intent string
}

var actionSpecs = map[string]actionSpec{
	"plan.run":     {Name: "plan.run", Intent: "read"},
	"plan.show":    {Name: "plan.show", Intent: "read"},
	"validate.run": {Name: "validate.run", Intent: "read"},
	"output.list":  {Name: "output.list", Intent: "read"},
	"apply.run":    {Name: "apply.run", Intent: "write"},
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
		Capabilities:    []string{"terraform"},
		Labels:          map[string]string{"adapter": "terraform"},
		Type:            "terraform",
	})
	if err != nil {
		return nil, err
	}

	return &Worker{
		cfg:     cfg,
		gateway: gatewayclient.New(cfg.GatewayURL, cfg.APIKey),
		redis:   redisClient,
		worker:  worker,
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

	actionKey := strings.ToLower(strings.TrimSpace(input.Action))
	if actionKey == "" {
		return w.failJob(jobID, fmt.Errorf("action required"))
	}

	spec, ok := actionSpecs[actionKey]
	if !ok {
		return w.failJob(jobID, fmt.Errorf("unsupported action: %s", actionKey))
	}
	if err := w.enforceTopic(req.GetTopic(), spec.Intent); err != nil {
		return w.failJob(jobID, err)
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return w.failJob(jobID, err)
	}
	if err := enforceActionPolicy(profile, spec.Name); err != nil {
		return w.failJob(jobID, err)
	}

	workDir, err := resolveWorkingDir(profile, params)
	if err != nil {
		return w.failJob(jobID, err)
	}
	if err := enforceDirPolicy(profile, workDir); err != nil {
		return w.failJob(jobID, err)
	}

	callCtx, cancel := context.WithTimeout(ctx, w.requestTimeout(profile))
	defer cancel()

	start := time.Now()
	result, err := w.execute(callCtx, profile, spec, workDir, params)

	call := callResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     spec.Name,
		Dir:        workDir,
		DurationMs: time.Since(start).Milliseconds(),
		Result:     result,
	}
	if err != nil {
		call.Error = err.Error()
	}
	if call.RequestID == "" && strings.TrimSpace(input.RequestID) != "" {
		call.RequestID = strings.TrimSpace(input.RequestID)
	}
	return w.finishJob(jobID, call, err)
}

func (w *Worker) fetchInput(ctx context.Context, ptr string) (JobInput, error) {
	if ptr == "" {
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

func (w *Worker) requestTimeout(profile config.Profile) time.Duration {
	if profile.Timeout > 0 {
		return profile.Timeout
	}
	return w.cfg.RequestTimeout
}

func (w *Worker) enforceTopic(topic, intent string) error {
	if topic == "" {
		return fmt.Errorf("job topic missing")
	}
	switch intent {
	case "read":
		if topic != "job.terraform.read" {
			return fmt.Errorf("read actions must use job.terraform.read topic")
		}
	case "write":
		if topic != "job.terraform.write" {
			return fmt.Errorf("write actions must use job.terraform.write topic")
		}
	default:
		return fmt.Errorf("unknown action intent: %s", intent)
	}
	return nil
}

func (w *Worker) execute(ctx context.Context, profile config.Profile, spec actionSpec, workDir string, params map[string]any) (any, error) {
	switch spec.Name {
	case "plan.run":
		return w.runPlan(ctx, profile, workDir, params)
	case "plan.show":
		return w.runPlanShow(ctx, profile, workDir, params)
	case "validate.run":
		return w.runValidate(ctx, profile, workDir, params)
	case "output.list":
		return w.runOutput(ctx, profile, workDir)
	case "apply.run":
		return w.runApply(ctx, profile, workDir, params)
	default:
		return nil, fmt.Errorf("unsupported action: %s", spec.Name)
	}
}

func (w *Worker) runPlan(ctx context.Context, profile config.Profile, workDir string, params map[string]any) (any, error) {
	if shouldInit(params) {
		if _, err := w.runInit(ctx, profile, workDir, params); err != nil {
			return nil, err
		}
	}

	args := []string{"plan", "-input=false", "-no-color"}
	if getBool(params, "refresh") == false {
		args = append(args, "-refresh=false")
	}
	if getBool(params, "destroy") {
		args = append(args, "-destroy")
	}
	if val, ok := getInt(params, "parallelism"); ok {
		args = append(args, "-parallelism", strconv.Itoa(val))
	}
	if val, ok := getString(params, "lock_timeout", "lockTimeout"); ok {
		args = append(args, "-lock-timeout", val)
	}
	if getBool(params, "detailed_exitcode") {
		args = append(args, "-detailed-exitcode")
	}
	if planOut, ok := getString(params, "out", "plan_file", "planFile"); ok {
		args = append(args, "-out", planOut)
	}
	args = appendVarFiles(args, params)
	args = appendVars(args, params)
	args = appendTargets(args, params)

	result, exitCode, err := w.runTerraform(ctx, profile, workDir, args)
	if err != nil {
		return nil, err
	}

	drifted := false
	if getBool(params, "detailed_exitcode") && exitCode == 2 {
		drifted = true
	}

	return map[string]any{
		"stdout":    result.Stdout,
		"stderr":    result.Stderr,
		"exit_code": exitCode,
		"drifted":   drifted,
	}, nil
}

func (w *Worker) runPlanShow(ctx context.Context, profile config.Profile, workDir string, params map[string]any) (any, error) {
	planFile, ok := getString(params, "plan_file", "planFile", "out")
	if !ok {
		return nil, fmt.Errorf("plan_file required")
	}

	args := []string{"show", "-json", planFile}
	result, _, err := w.runTerraform(ctx, profile, workDir, args)
	if err != nil {
		return nil, err
	}

	var decoded any
	if err := json.Unmarshal([]byte(result.Stdout), &decoded); err != nil {
		return map[string]any{"stdout": result.Stdout, "stderr": result.Stderr}, nil
	}
	return decoded, nil
}

func (w *Worker) runValidate(ctx context.Context, profile config.Profile, workDir string, params map[string]any) (any, error) {
	args := []string{"validate", "-no-color"}
	if getBool(params, "json") {
		args = append(args, "-json")
	}

	result, _, err := w.runTerraform(ctx, profile, workDir, args)
	if err != nil {
		return nil, err
	}

	if getBool(params, "json") {
		var decoded any
		if err := json.Unmarshal([]byte(result.Stdout), &decoded); err == nil {
			return decoded, nil
		}
	}
	return map[string]any{"stdout": result.Stdout, "stderr": result.Stderr}, nil
}

func (w *Worker) runOutput(ctx context.Context, profile config.Profile, workDir string) (any, error) {
	args := []string{"output", "-json"}
	result, _, err := w.runTerraform(ctx, profile, workDir, args)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal([]byte(result.Stdout), &decoded); err != nil {
		return map[string]any{"stdout": result.Stdout, "stderr": result.Stderr}, nil
	}
	return decoded, nil
}

func (w *Worker) runApply(ctx context.Context, profile config.Profile, workDir string, params map[string]any) (any, error) {
	if shouldInit(params) {
		if _, err := w.runInit(ctx, profile, workDir, params); err != nil {
			return nil, err
		}
	}

	args := []string{"apply", "-input=false", "-no-color"}
	planFile, hasPlan := getString(params, "plan_file", "planFile", "out")
	if hasPlan {
		args = append(args, planFile)
	} else if getBool(params, "auto_approve") {
		args = append(args, "-auto-approve")
	} else {
		return nil, fmt.Errorf("apply requires plan_file or auto_approve")
	}

	if val, ok := getInt(params, "parallelism"); ok {
		args = append(args, "-parallelism", strconv.Itoa(val))
	}
	if val, ok := getString(params, "lock_timeout", "lockTimeout"); ok {
		args = append(args, "-lock-timeout", val)
	}

	if !hasPlan {
		args = appendVarFiles(args, params)
		args = appendVars(args, params)
		args = appendTargets(args, params)
	}

	result, _, err := w.runTerraform(ctx, profile, workDir, args)
	if err != nil {
		return nil, err
	}
	return map[string]any{"stdout": result.Stdout, "stderr": result.Stderr}, nil
}

func (w *Worker) runInit(ctx context.Context, profile config.Profile, workDir string, params map[string]any) (any, error) {
	args := []string{"init", "-input=false", "-no-color"}
	if getBool(params, "upgrade") {
		args = append(args, "-upgrade")
	}
	if getBool(params, "reconfigure") {
		args = append(args, "-reconfigure")
	}
	args = appendBackendConfig(args, params)

	result, _, err := w.runTerraform(ctx, profile, workDir, args)
	if err != nil {
		return nil, err
	}
	return map[string]any{"stdout": result.Stdout, "stderr": result.Stderr}, nil
}

type commandResult struct {
	Stdout string
	Stderr string
}

func (w *Worker) runTerraform(ctx context.Context, profile config.Profile, workDir string, args []string) (commandResult, int, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, profile.CommandTimeout)
	defer cancel()

	// #nosec G204 -- terraform path comes from profile config; args are built from allowlisted actions without shell.
	cmd := exec.CommandContext(cmdCtx, profile.TerraformPath, args...)
	cmd.Dir = workDir

	env := append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=0")
	for key, value := range profile.Env {
		if strings.TrimSpace(key) == "" {
			continue
		}
		env = append(env, key+"="+value)
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := commandResult{Stdout: strings.TrimSpace(stdout.String()), Stderr: strings.TrimSpace(stderr.String())}

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return result, exitCode, err
		}
	}
	if exitCode != 0 {
		return result, exitCode, fmt.Errorf("terraform %s failed: %s", strings.Join(args, " "), result.Stderr)
	}
	return result, exitCode, nil
}

func shouldInit(params map[string]any) bool {
	if val, ok := params["init"]; ok {
		switch typed := val.(type) {
		case bool:
			return typed
		case string:
			return strings.EqualFold(strings.TrimSpace(typed), "true")
		}
	}
	return true
}

func resolveWorkingDir(profile config.Profile, params map[string]any) (string, error) {
	if dir, ok := getString(params, "dir", "working_dir", "path"); ok {
		return normalizeDir(profile.WorkingDir, dir)
	}
	if strings.TrimSpace(profile.WorkingDir) != "" {
		return normalizeDir("", profile.WorkingDir)
	}
	return "", fmt.Errorf("dir required")
}

func normalizeDir(baseDir, dir string) (string, error) {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return "", fmt.Errorf("dir required")
	}
	candidate := trimmed
	if !filepath.IsAbs(candidate) && strings.TrimSpace(baseDir) != "" {
		candidate = filepath.Join(baseDir, candidate)
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("dir is not a directory: %s", abs)
	}
	return abs, nil
}

func enforceDirPolicy(profile config.Profile, dir string) error {
	if len(profile.AllowedDirs) == 0 && len(profile.DeniedDirs) == 0 {
		return nil
	}
	normalized := normalizeForMatch(dir)
	if strings.TrimSpace(normalized) == "" {
		return fmt.Errorf("dir required for policy enforcement")
	}
	if len(profile.AllowedDirs) > 0 && !matchAny(profile.AllowedDirs, normalized) {
		return fmt.Errorf("dir not allowed: %s", dir)
	}
	if matchAny(profile.DeniedDirs, normalized) {
		return fmt.Errorf("dir denied: %s", dir)
	}
	return nil
}

func normalizeForMatch(dir string) string {
	return filepath.ToSlash(filepath.Clean(dir))
}

func enforceActionPolicy(profile config.Profile, action string) error {
	if len(profile.AllowActions) > 0 && !matchAny(profile.AllowActions, action) {
		return fmt.Errorf("action not allowed: %s", action)
	}
	if matchAny(profile.DenyActions, action) {
		return fmt.Errorf("action denied: %s", action)
	}
	return nil
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

func appendVarFiles(args []string, params map[string]any) []string {
	for _, key := range []string{"var_file", "var_files", "varFile", "varFiles"} {
		if values := extractStringList(params, key); len(values) > 0 {
			for _, value := range values {
				args = append(args, "-var-file", value)
			}
		}
	}
	return args
}

func appendVars(args []string, params map[string]any) []string {
	if values, ok := params["var"]; ok {
		switch typed := values.(type) {
		case map[string]any:
			for key, val := range typed {
				args = append(args, "-var", fmt.Sprintf("%s=%v", key, val))
			}
		case map[string]string:
			for key, val := range typed {
				args = append(args, "-var", fmt.Sprintf("%s=%s", key, val))
			}
		case []any:
			for _, item := range typed {
				if str, ok := coerceString(item); ok {
					args = append(args, "-var", str)
				}
			}
		case []string:
			for _, item := range typed {
				if strings.TrimSpace(item) != "" {
					args = append(args, "-var", item)
				}
			}
		case string:
			if strings.TrimSpace(typed) != "" {
				args = append(args, "-var", typed)
			}
		}
	}
	return args
}

func appendTargets(args []string, params map[string]any) []string {
	if values := extractStringList(params, "target", "targets"); len(values) > 0 {
		for _, value := range values {
			args = append(args, "-target", value)
		}
	}
	return args
}

func appendBackendConfig(args []string, params map[string]any) []string {
	value, ok := params["backend_config"]
	if !ok {
		value, ok = params["backendConfig"]
	}
	if !ok {
		return args
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, val := range typed {
			args = append(args, "-backend-config", fmt.Sprintf("%s=%v", key, val))
		}
	case map[string]string:
		for key, val := range typed {
			args = append(args, "-backend-config", fmt.Sprintf("%s=%s", key, val))
		}
	case []any:
		for _, item := range typed {
			if str, ok := coerceString(item); ok {
				args = append(args, "-backend-config", str)
			}
		}
	case []string:
		for _, item := range typed {
			if strings.TrimSpace(item) != "" {
				args = append(args, "-backend-config", item)
			}
		}
	case string:
		if strings.TrimSpace(typed) != "" {
			args = append(args, "-backend-config", typed)
		}
	}
	return args
}

func extractStringList(params map[string]any, keys ...string) []string {
	for _, key := range keys {
		if val, ok := params[key]; ok {
			switch typed := val.(type) {
			case []string:
				return typed
			case []any:
				out := make([]string, 0, len(typed))
				for _, item := range typed {
					if str, ok := coerceString(item); ok {
						out = append(out, str)
					}
				}
				return out
			case string:
				if strings.TrimSpace(typed) != "" {
					return []string{typed}
				}
			}
		}
	}
	return nil
}

func getString(params map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if val, ok := params[key]; ok {
			if str, ok := coerceString(val); ok {
				return str, true
			}
		}
	}
	return "", false
}

func getBool(params map[string]any, key string) bool {
	if val, ok := params[key]; ok {
		switch typed := val.(type) {
		case bool:
			return typed
		case string:
			return strings.EqualFold(strings.TrimSpace(typed), "true")
		}
	}
	return false
}

func getInt(params map[string]any, key string) (int, bool) {
	if val, ok := params[key]; ok {
		switch typed := val.(type) {
		case int:
			return typed, true
		case int64:
			return int(typed), true
		case float64:
			return int(typed), true
		case string:
			if num, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
				return num, true
			}
		}
	}
	return 0, false
}

func coerceString(value any) (string, bool) {
	switch val := value.(type) {
	case string:
		trimmed := strings.TrimSpace(val)
		if trimmed == "" {
			return "", false
		}
		return trimmed, true
	case fmt.Stringer:
		trimmed := strings.TrimSpace(val.String())
		if trimmed == "" {
			return "", false
		}
		return trimmed, true
	case int:
		return fmt.Sprintf("%d", val), true
	case int64:
		return fmt.Sprintf("%d", val), true
	case float64:
		return fmt.Sprintf("%v", val), true
	default:
		return "", false
	}
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
