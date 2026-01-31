package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	"github.com/cordum-io/cordum-packs/packs/kubernetes-triage/internal/config"
)

type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
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
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
}

type actionSpec struct {
	Name         string
	Intent       string
	RequiredKeys []string
	Namespaced   bool
	OutputJSON   bool
}

var actionSpecs = map[string]actionSpec{
	"pods.list":           {Name: "pods.list", Intent: "read", Namespaced: true, OutputJSON: true},
	"pods.get":            {Name: "pods.get", Intent: "read", Namespaced: true, OutputJSON: true, RequiredKeys: []string{"name"}},
	"pods.logs":           {Name: "pods.logs", Intent: "read", Namespaced: true, OutputJSON: false, RequiredKeys: []string{"name"}},
	"events.list":         {Name: "events.list", Intent: "read", Namespaced: true, OutputJSON: true},
	"deployments.list":    {Name: "deployments.list", Intent: "read", Namespaced: true, OutputJSON: true},
	"deployments.get":     {Name: "deployments.get", Intent: "read", Namespaced: true, OutputJSON: true, RequiredKeys: []string{"name"}},
	"nodes.list":          {Name: "nodes.list", Intent: "read", Namespaced: false, OutputJSON: true},
	"rollouts.status":     {Name: "rollouts.status", Intent: "read", Namespaced: true, OutputJSON: false, RequiredKeys: []string{"name"}},
	"deployments.restart": {Name: "deployments.restart", Intent: "write", Namespaced: true, OutputJSON: false, RequiredKeys: []string{"name"}},
	"deployments.scale":   {Name: "deployments.scale", Intent: "write", Namespaced: true, OutputJSON: false, RequiredKeys: []string{"name", "replicas"}},
	"pods.delete":         {Name: "pods.delete", Intent: "write", Namespaced: true, OutputJSON: false, RequiredKeys: []string{"name"}},
}

func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := runtime.ResolveWorkerID("", "kubernetes-triage")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, err
	}
	store, err := runtime.NewRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		return nil, err
	}

	agent := &runtime.Agent{
		NATS:     nc,
		Store:    store,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	w := &Worker{
		cfg:      cfg,
		agent:    agent,
		natsConn: nc,
		workerID: workerID,
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
	return nil
}

func (w *Worker) Run(ctx context.Context) error {
	if w.agent == nil {
		return fmt.Errorf("runtime agent unavailable")
	}
	subjects := w.cfg.Subjects
	if len(subjects) == 0 {
		subjects = []string{"job.kubernetes-triage.*"}
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

	actionKey := strings.ToLower(strings.TrimSpace(input.Action))
	if actionKey == "" {
		return callResult{}, fmt.Errorf("action required")
	}
	spec, ok := actionSpecs[actionKey]
	if !ok {
		return callResult{}, fmt.Errorf("unsupported action: %s", actionKey)
	}
	if err := w.enforceTopic(ctx.Job.GetTopic(), spec.Intent); err != nil {
		return callResult{}, err
	}

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}
	if err := validateParams(params, spec.RequiredKeys); err != nil {
		return callResult{}, err
	}

	profile, err := w.resolveProfile(input.Profile)
	if err != nil {
		return callResult{}, err
	}
	if err := enforceActionPolicy(profile, spec.Name); err != nil {
		return callResult{}, err
	}

	namespace := resolveNamespace(profile, params, spec.Namespaced)
	if spec.Namespaced {
		if err := enforceNamespacePolicy(profile, namespace); err != nil {
			return callResult{}, err
		}
	}

	callCtx, cancel := context.WithTimeout(context.Background(), w.requestTimeout(profile))
	defer cancel()

	start := time.Now()
	resultPayload, err := w.execute(callCtx, profile, spec, namespace, params)

	result := callResult{
		JobID:      jobID,
		Profile:    profile.Name,
		Action:     spec.Name,
		DurationMs: time.Since(start).Milliseconds(),
		Result:     resultPayload,
	}
	if strings.TrimSpace(input.RequestID) != "" {
		result.RequestID = strings.TrimSpace(input.RequestID)
	}
	if err != nil {
		result.Error = err.Error()
	}
	return result, err
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
		if topic != "job.kubernetes-triage.read" {
			return fmt.Errorf("read actions must use job.kubernetes-triage.read topic")
		}
	case "write":
		if topic != "job.kubernetes-triage.write" {
			return fmt.Errorf("write actions must use job.kubernetes-triage.write topic")
		}
	default:
		return fmt.Errorf("unknown action intent: %s", intent)
	}
	return nil
}

func (w *Worker) execute(ctx context.Context, profile config.Profile, spec actionSpec, namespace string, params map[string]any) (any, error) {
	args, err := buildKubectlArgs(profile, spec, namespace, params)
	if err != nil {
		return nil, err
	}
	cmdCtx, cancel := context.WithTimeout(ctx, profile.CommandTimeout)
	defer cancel()

	// #nosec G204 -- kubectl path comes from profile config; args are built from allowlisted actions without shell.
	cmd := exec.CommandContext(cmdCtx, profile.KubectlPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl %s failed: %w: %s", spec.Name, err, strings.TrimSpace(string(output)))
	}
	if !spec.OutputJSON {
		return strings.TrimSpace(string(output)), nil
	}
	var decoded any
	if err := json.Unmarshal(output, &decoded); err != nil {
		return strings.TrimSpace(string(output)), nil
	}
	return decoded, nil
}

func buildKubectlArgs(profile config.Profile, spec actionSpec, namespace string, params map[string]any) ([]string, error) {
	args := []string{}
	if strings.TrimSpace(profile.Kubeconfig) != "" {
		args = append(args, "--kubeconfig", profile.Kubeconfig)
	}
	if strings.TrimSpace(profile.Context) != "" {
		args = append(args, "--context", profile.Context)
	}
	if spec.Namespaced {
		args = append(args, "-n", namespace)
	}

	name, _ := getString(params, "name")
	labelSelector, _ := getString(params, "label_selector", "labelSelector")
	fieldSelector, _ := getString(params, "field_selector", "fieldSelector")
	container, _ := getString(params, "container")

	switch spec.Name {
	case "pods.list":
		args = append(args, "get", "pods", "-o", "json")
		args = appendSelectors(args, labelSelector, fieldSelector)
	case "pods.get":
		if name == "" {
			return nil, fmt.Errorf("name required")
		}
		args = append(args, "get", "pod", name, "-o", "json")
	case "pods.logs":
		if name == "" {
			return nil, fmt.Errorf("name required")
		}
		args = append(args, "logs", name)
		if container != "" {
			args = append(args, "-c", container)
		}
		if tail, ok := getInt(params, "tail_lines", "tailLines"); ok {
			args = append(args, "--tail", strconv.Itoa(tail))
		}
		if since, ok := getInt(params, "since_seconds", "sinceSeconds"); ok {
			args = append(args, "--since", fmt.Sprintf("%ds", since))
		}
		if ts, ok := getBool(params, "timestamps"); ok && ts {
			args = append(args, "--timestamps")
		}
		if prev, ok := getBool(params, "previous"); ok && prev {
			args = append(args, "--previous")
		}
	case "events.list":
		args = append(args, "get", "events", "-o", "json")
		args = appendSelectors(args, labelSelector, fieldSelector)
	case "deployments.list":
		args = append(args, "get", "deployments", "-o", "json")
		args = appendSelectors(args, labelSelector, fieldSelector)
	case "deployments.get":
		if name == "" {
			return nil, fmt.Errorf("name required")
		}
		args = append(args, "get", "deployment", name, "-o", "json")
	case "nodes.list":
		args = append(args, "get", "nodes", "-o", "json")
	case "rollouts.status":
		if name == "" {
			return nil, fmt.Errorf("name required")
		}
		args = append(args, "rollout", "status", "deployment/"+name, "--watch=false")
	case "deployments.restart":
		if name == "" {
			return nil, fmt.Errorf("name required")
		}
		args = append(args, "rollout", "restart", "deployment/"+name)
	case "deployments.scale":
		if name == "" {
			return nil, fmt.Errorf("name required")
		}
		replicas, ok := getInt(params, "replicas")
		if !ok {
			return nil, fmt.Errorf("replicas required")
		}
		args = append(args, "scale", "deployment/"+name, "--replicas", strconv.Itoa(replicas))
	case "pods.delete":
		if name == "" {
			return nil, fmt.Errorf("name required")
		}
		args = append(args, "delete", "pod", name)
	default:
		return nil, fmt.Errorf("unsupported action: %s", spec.Name)
	}
	return args, nil
}

func appendSelectors(args []string, labelSelector, fieldSelector string) []string {
	if labelSelector != "" {
		args = append(args, "-l", labelSelector)
	}
	if fieldSelector != "" {
		args = append(args, "--field-selector", fieldSelector)
	}
	return args
}

func resolveNamespace(profile config.Profile, params map[string]any, namespaced bool) string {
	if !namespaced {
		return ""
	}
	if value, ok := getString(params, "namespace", "ns"); ok && value != "" {
		return value
	}
	return profile.Namespace
}

func enforceNamespacePolicy(profile config.Profile, namespace string) error {
	if len(profile.AllowedNamespaces) == 0 && len(profile.DeniedNamespaces) == 0 {
		return nil
	}
	if namespace == "" {
		return fmt.Errorf("namespace required for policy enforcement")
	}
	if len(profile.AllowedNamespaces) > 0 && !matchAny(profile.AllowedNamespaces, namespace) {
		return fmt.Errorf("namespace not allowed: %s", namespace)
	}
	if matchAny(profile.DeniedNamespaces, namespace) {
		return fmt.Errorf("namespace denied: %s", namespace)
	}
	return nil
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

func validateParams(params map[string]any, required []string) error {
	for _, key := range required {
		alternatives := strings.Split(key, "|")
		found := false
		for _, alt := range alternatives {
			if hasParam(params, alt) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing required param: %s", key)
		}
	}
	return nil
}

func hasParam(params map[string]any, key string) bool {
	value, ok := params[key]
	if !ok {
		return false
	}
	switch val := value.(type) {
	case string:
		return strings.TrimSpace(val) != ""
	case []any:
		return len(val) > 0
	case []string:
		return len(val) > 0
	default:
		return true
	}
}

func getString(params map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := params[key]; ok {
			if str, ok := coerceString(value); ok {
				return str, true
			}
		}
	}
	return "", false
}

func getInt(params map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		if value, ok := params[key]; ok {
			switch val := value.(type) {
			case float64:
				return int(val), true
			case int:
				return val, true
			case int64:
				return int(val), true
			case string:
				if parsed, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
					return parsed, true
				}
			}
		}
	}
	return 0, false
}

func getBool(params map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if value, ok := params[key]; ok {
			switch val := value.(type) {
			case bool:
				return val, true
			case string:
				if parsed, err := strconv.ParseBool(strings.TrimSpace(val)); err == nil {
					return parsed, true
				}
			}
		}
	}
	return false, false
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
