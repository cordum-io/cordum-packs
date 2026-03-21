package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	azureclient "github.com/cordum-io/cordum-packs/packs/azure/internal/azureclient"
	"github.com/cordum-io/cordum-packs/packs/azure/internal/config"
	"github.com/cordum-io/cordum-packs/packs/azure/internal/services"
)

const (
	topicRead  = "job.azure.read"
	topicWrite = "job.azure.write"
)

type actionSpec struct {
	Intent  string
	Service string
}

var actionSpecs = map[string]actionSpec{
	// Functions
	"functions.invoke":    {Intent: "write", Service: "functions"},
	"functions.list_apps": {Intent: "read", Service: "functions"},
	// Blob
	"blob.get":             {Intent: "read", Service: "blob"},
	"blob.upload":          {Intent: "write", Service: "blob"},
	"blob.list":            {Intent: "read", Service: "blob"},
	"blob.list_containers": {Intent: "read", Service: "blob"},
	"blob.delete":          {Intent: "write", Service: "blob"},
	// Service Bus
	"servicebus.send": {Intent: "write", Service: "servicebus"},
	"servicebus.peek": {Intent: "read", Service: "servicebus"},
	// Compute
	"compute.list_vms":              {Intent: "read", Service: "compute"},
	"compute.get_vm":                {Intent: "read", Service: "compute"},
	"compute.get_vm_instance_view":  {Intent: "read", Service: "compute"},
	// Monitor
	"monitor.query_metrics":   {Intent: "read", Service: "monitor"},
	"monitor.list_alert_rules": {Intent: "read", Service: "monitor"},
	// Key Vault
	"keyvault.get_secret":  {Intent: "read", Service: "keyvault"},
	"keyvault.list_secrets": {Intent: "read", Service: "keyvault"},
	// Entra ID
	"entra.get_user":    {Intent: "read", Service: "entra"},
	"entra.list_users":  {Intent: "read", Service: "entra"},
	"entra.list_groups": {Intent: "read", Service: "entra"},
}

// Worker handles Azure pack jobs.
type Worker struct {
	cfg      config.Config
	agent    *runtime.Agent
	natsConn *nats.Conn
	workerID string
	sem      chan struct{}
	active   int32
}

// JobInput is the incoming job payload.
type JobInput struct {
	Profile        string         `json:"profile"`
	Action         string         `json:"action"`
	SubscriptionID string         `json:"subscription_id"`
	ResourceGroup  string         `json:"resource_group"`
	Params         map[string]any `json:"params"`
	RequestID      string         `json:"request_id"`
}

// JobResult is the output payload.
type JobResult struct {
	JobID          string `json:"job_id"`
	Profile        string `json:"profile"`
	Action         string `json:"action"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	StatusCode     int    `json:"status_code"`
	RequestID      string `json:"request_id,omitempty"`
	DurationMs     int64  `json:"duration_ms"`
	Result         any    `json:"result,omitempty"`
	Error          string `json:"error,omitempty"`
}

// New creates a new Azure worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "azure")
	nc, err := nats.Connect(cfg.NatsURL, nats.Name(workerID), nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	store, err := newRedisBlobStoreWithTTL(cfg.RedisURL, cfg.ResultTTL)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("redis store: %w", err)
	}

	runtimeAgent := &runtime.Agent{
		NATS:     nc,
		Store:    store,
		RedisURL: cfg.RedisURL,
		SenderID: workerID,
	}

	w := &Worker{
		cfg:      cfg,
		agent:    runtimeAgent,
		natsConn: nc,
		workerID: workerID,
	}
	if cfg.MaxParallel > 0 {
		w.sem = make(chan struct{}, cfg.MaxParallel)
	}
	return w, nil
}

// Close shuts down the worker.
func (w *Worker) Close() error {
	if w.agent != nil {
		_ = w.agent.Close()
	}
	return nil
}

// Run starts the worker.
func (w *Worker) Run(ctx context.Context) error {
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
		return fmt.Errorf("agent start: %w", err)
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

	slog.Info("azure worker started", "worker_id", w.workerID, "subjects", subjects)
	<-ctx.Done()
	return ctx.Err()
}

func (w *Worker) handleJob(rctx runtime.Context, payload map[string]any) (JobResult, error) {
	if w.sem != nil {
		w.sem <- struct{}{}
		atomic.AddInt32(&w.active, 1)
		defer func() {
			<-w.sem
			atomic.AddInt32(&w.active, -1)
		}()
	}

	start := time.Now()
	jobID := rctx.Job.GetJobId()
	topic := rctx.Job.GetTopic()

	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.RequestTimeout)
	defer cancel()

	payload = normalizePayload(payload)

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		return JobResult{JobID: jobID, Error: fmt.Sprintf("decode input: %v", err)}, nil
	}

	action := strings.TrimSpace(input.Action)
	if action == "" {
		return JobResult{JobID: jobID, Error: "action is required"}, nil
	}

	spec, ok := actionSpecs[action]
	if !ok {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("unsupported action: %s", action)}, nil
	}

	// Topic-intent enforcement
	topicIntent := "read"
	if topic == topicWrite {
		topicIntent = "write"
	}
	if spec.Intent == "write" && topicIntent == "read" {
		return JobResult{
			JobID:  jobID,
			Action: action,
			Error:  fmt.Sprintf("action %q requires write topic but was sent to %s", action, topic),
		}, nil
	}

	// Profile resolution
	profile := w.cfg.ResolveProfile(input.Profile)
	if !profile.IsActionAllowed(action) {
		return JobResult{
			JobID:   jobID,
			Action:  action,
			Profile: profile.Name,
			Error:   fmt.Sprintf("action %q is not allowed by profile %q", action, profile.Name),
		}, nil
	}

	// Build Azure credential + client
	cred, err := azureclient.NewCredential(profile)
	if err != nil {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("azure credential: %v", err)}, nil
	}

	azClient := services.NewAzureClient(cred)
	subscriptionID := azureclient.ResolveSubscriptionID(input.SubscriptionID, profile)
	resourceGroup := azureclient.ResolveResourceGroup(input.ResourceGroup, profile)

	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	// Dispatch
	result, err := dispatchAction(ctx, azClient, action, spec, subscriptionID, resourceGroup, params)

	var jobResult JobResult
	jobResult.JobID = jobID
	jobResult.Profile = profile.Name
	jobResult.Action = action
	jobResult.SubscriptionID = subscriptionID
	jobResult.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		jobResult.Error = err.Error()
	} else {
		jobResult.Result = result
		jobResult.StatusCode = 200
	}

	slog.Info("azure job completed",
		"job_id", jobID, "action", action, "service", spec.Service,
		"duration_ms", jobResult.DurationMs, "error", jobResult.Error,
	)

	return jobResult, nil
}

func dispatchAction(ctx context.Context, client *services.AzureClient, action string, spec actionSpec, subscriptionID, resourceGroup string, params map[string]any) (any, error) {
	switch spec.Service {
	case "functions":
		svc := services.NewFunctionsService(client, subscriptionID, resourceGroup)
		switch action {
		case "functions.invoke":
			return svc.InvokeFunction(ctx, params)
		case "functions.list_apps":
			return svc.ListFunctionApps(ctx, params)
		}
	case "blob":
		svc := services.NewBlobService(client)
		switch action {
		case "blob.get":
			return svc.GetBlob(ctx, params)
		case "blob.upload":
			return svc.UploadBlob(ctx, params)
		case "blob.list":
			return svc.ListBlobs(ctx, params)
		case "blob.list_containers":
			return svc.ListContainers(ctx, params)
		case "blob.delete":
			return svc.DeleteBlob(ctx, params)
		}
	case "servicebus":
		svc := services.NewServiceBusService(client)
		switch action {
		case "servicebus.send":
			return svc.SendMessage(ctx, params)
		case "servicebus.peek":
			return svc.PeekMessages(ctx, params)
		}
	case "compute":
		svc := services.NewComputeService(client, subscriptionID, resourceGroup)
		switch action {
		case "compute.list_vms":
			return svc.ListVMs(ctx, params)
		case "compute.get_vm":
			return svc.GetVM(ctx, params)
		case "compute.get_vm_instance_view":
			return svc.GetVMInstanceView(ctx, params)
		}
	case "monitor":
		svc := services.NewMonitorService(client, subscriptionID, resourceGroup)
		switch action {
		case "monitor.query_metrics":
			return svc.QueryMetrics(ctx, params)
		case "monitor.list_alert_rules":
			return svc.ListAlertRules(ctx, params)
		}
	case "keyvault":
		svc := services.NewKeyVaultService(client)
		switch action {
		case "keyvault.get_secret":
			return svc.GetSecret(ctx, params)
		case "keyvault.list_secrets":
			return svc.ListSecrets(ctx, params)
		}
	case "entra":
		svc := services.NewEntraService(client)
		switch action {
		case "entra.get_user":
			return svc.GetUser(ctx, params)
		case "entra.list_users":
			return svc.ListUsers(ctx, params)
		case "entra.list_groups":
			return svc.ListGroups(ctx, params)
		}
	}
	return nil, fmt.Errorf("unhandled action: %s", action)
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
