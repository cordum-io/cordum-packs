package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cordum/cordum/sdk/runtime"
	"github.com/nats-io/nats.go"

	awsclient "github.com/cordum-io/cordum-packs/packs/aws/internal/awsclient"
	"github.com/cordum-io/cordum-packs/packs/aws/internal/config"
	"github.com/cordum-io/cordum-packs/packs/aws/internal/services"
)

const (
	topicRead  = "job.aws.read"
	topicWrite = "job.aws.write"
)

// actionSpec maps an action name to its intent (read or write).
type actionSpec struct {
	Intent  string // "read" or "write"
	Service string // "lambda", "s3", etc.
}

// All supported actions with their intent classification.
var actionSpecs = map[string]actionSpec{
	// Lambda
	"lambda.invoke":         {Intent: "write", Service: "lambda"},
	"lambda.get_function":   {Intent: "read", Service: "lambda"},
	"lambda.list_functions":  {Intent: "read", Service: "lambda"},
	// S3
	"s3.get_object":    {Intent: "read", Service: "s3"},
	"s3.put_object":    {Intent: "write", Service: "s3"},
	"s3.list_buckets":  {Intent: "read", Service: "s3"},
	"s3.list_objects":  {Intent: "read", Service: "s3"},
	"s3.head_object":   {Intent: "read", Service: "s3"},
	"s3.delete_object": {Intent: "write", Service: "s3"},
	// SQS
	"sqs.send_message":    {Intent: "write", Service: "sqs"},
	"sqs.receive_message": {Intent: "read", Service: "sqs"},
	"sqs.get_queue_url":   {Intent: "read", Service: "sqs"},
	"sqs.list_queues":     {Intent: "read", Service: "sqs"},
	// SNS
	"sns.publish":            {Intent: "write", Service: "sns"},
	"sns.list_topics":        {Intent: "read", Service: "sns"},
	"sns.list_subscriptions": {Intent: "read", Service: "sns"},
	// EC2 (describe only)
	"ec2.describe_instances":       {Intent: "read", Service: "ec2"},
	"ec2.describe_security_groups": {Intent: "read", Service: "ec2"},
	"ec2.describe_vpcs":            {Intent: "read", Service: "ec2"},
	// CloudWatch
	"cloudwatch.get_metric_data": {Intent: "read", Service: "cloudwatch"},
	"cloudwatch.list_metrics":    {Intent: "read", Service: "cloudwatch"},
	"cloudwatch.describe_alarms": {Intent: "read", Service: "cloudwatch"},
	// IAM (read only)
	"iam.get_user":      {Intent: "read", Service: "iam"},
	"iam.list_users":    {Intent: "read", Service: "iam"},
	"iam.list_roles":    {Intent: "read", Service: "iam"},
	"iam.list_policies": {Intent: "read", Service: "iam"},
	// Secrets Manager
	"secretsmanager.get_secret_value": {Intent: "read", Service: "secretsmanager"},
	"secretsmanager.list_secrets":     {Intent: "read", Service: "secretsmanager"},
	"secretsmanager.describe_secret":  {Intent: "read", Service: "secretsmanager"},
}

// Worker handles AWS pack jobs.
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
	Profile   string         `json:"profile"`
	Action    string         `json:"action"`
	Region    string         `json:"region"`
	Params    map[string]any `json:"params"`
	RequestID string         `json:"request_id"`
}

// JobResult is the output payload.
type JobResult struct {
	JobID      string `json:"job_id"`
	Profile    string `json:"profile"`
	Action     string `json:"action"`
	Region     string `json:"region,omitempty"`
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	Result     any    `json:"result,omitempty"`
	Error      string `json:"error,omitempty"`
}

// New creates a new AWS worker.
func New(cfg config.Config) (*Worker, error) {
	if cfg.NatsURL == "" {
		return nil, fmt.Errorf("nats url required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("redis url required")
	}

	workerID := resolveWorkerID("", "aws")
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

// Run starts the worker and blocks until ctx is done.
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

	slog.Info("aws worker started", "worker_id", w.workerID, "subjects", subjects)

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

	// Look up action spec
	spec, ok := actionSpecs[action]
	if !ok {
		return JobResult{JobID: jobID, Action: action, Error: fmt.Sprintf("unsupported action: %s", action)}, nil
	}

	// Enforce topic→intent: read topic can only execute read actions
	topicIntent := "read"
	if topic == topicWrite {
		topicIntent = "write"
	}
	if spec.Intent == "write" && topicIntent == "read" {
		return JobResult{
			JobID:  jobID,
			Action: action,
			Error:  fmt.Sprintf("action %q requires write topic (job.aws.write) but was sent to %s", action, topic),
		}, nil
	}

	// Resolve profile and check action/resource permissions
	profile := w.cfg.ResolveProfile(input.Profile)
	if !profile.IsActionAllowed(action) {
		return JobResult{
			JobID:   jobID,
			Action:  action,
			Profile: profile.Name,
			Error:   fmt.Sprintf("action %q is not allowed by profile %q", action, profile.Name),
		}, nil
	}

	// Check resource permission
	resourceARN := extractResourceARN(action, input.Params)
	if !profile.IsResourceAllowed(resourceARN) {
		return JobResult{
			JobID:   jobID,
			Action:  action,
			Profile: profile.Name,
			Error:   fmt.Sprintf("resource %q is not allowed by profile %q", resourceARN, profile.Name),
		}, nil
	}

	// Build AWS config for this request
	region := awsclient.ResolveRegion(input.Region, profile)
	awsCfg, err := awsclient.NewAWSConfig(ctx, profile, region)
	if err != nil {
		return JobResult{
			JobID:  jobID,
			Action: action,
			Region: region,
			Error:  fmt.Sprintf("aws config: %v", err),
		}, nil
	}

	// Dispatch to service
	params := input.Params
	if params == nil {
		params = map[string]any{}
	}

	result, err := dispatchAction(ctx, awsCfg, action, spec, params)

	var jobResult JobResult
	jobResult.JobID = jobID
	jobResult.Profile = profile.Name
	jobResult.Action = action
	jobResult.Region = region
	jobResult.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		jobResult.Error = err.Error()
	} else {
		jobResult.Result = result
		jobResult.StatusCode = 200
	}

	slog.Info("aws job completed",
		"job_id", jobID,
		"action", action,
		"service", spec.Service,
		"region", region,
		"duration_ms", jobResult.DurationMs,
		"error", jobResult.Error,
	)

	return jobResult, nil
}

// dispatchAction routes to the correct service method.
func dispatchAction(ctx context.Context, cfg aws.Config, action string, spec actionSpec, params map[string]any) (any, error) {
	switch spec.Service {
	case "lambda":
		svc := services.NewLambdaService(cfg)
		switch action {
		case "lambda.invoke":
			return svc.Invoke(ctx, params)
		case "lambda.get_function":
			return svc.GetFunction(ctx, params)
		case "lambda.list_functions":
			return svc.ListFunctions(ctx, params)
		}

	case "s3":
		svc := services.NewS3Service(cfg)
		switch action {
		case "s3.get_object":
			return svc.GetObject(ctx, params)
		case "s3.put_object":
			return svc.PutObject(ctx, params)
		case "s3.list_buckets":
			return svc.ListBuckets(ctx, params)
		case "s3.list_objects":
			return svc.ListObjects(ctx, params)
		case "s3.head_object":
			return svc.HeadObject(ctx, params)
		case "s3.delete_object":
			return svc.DeleteObject(ctx, params)
		}

	case "sqs":
		svc := services.NewSQSService(cfg)
		switch action {
		case "sqs.send_message":
			return svc.SendMessage(ctx, params)
		case "sqs.receive_message":
			return svc.ReceiveMessage(ctx, params)
		case "sqs.get_queue_url":
			return svc.GetQueueURL(ctx, params)
		case "sqs.list_queues":
			return svc.ListQueues(ctx, params)
		}

	case "sns":
		svc := services.NewSNSService(cfg)
		switch action {
		case "sns.publish":
			return svc.Publish(ctx, params)
		case "sns.list_topics":
			return svc.ListTopics(ctx, params)
		case "sns.list_subscriptions":
			return svc.ListSubscriptions(ctx, params)
		}

	case "ec2":
		svc := services.NewEC2Service(cfg)
		switch action {
		case "ec2.describe_instances":
			return svc.DescribeInstances(ctx, params)
		case "ec2.describe_security_groups":
			return svc.DescribeSecurityGroups(ctx, params)
		case "ec2.describe_vpcs":
			return svc.DescribeVPCs(ctx, params)
		}

	case "cloudwatch":
		svc := services.NewCloudWatchService(cfg)
		switch action {
		case "cloudwatch.get_metric_data":
			return svc.GetMetricData(ctx, params)
		case "cloudwatch.list_metrics":
			return svc.ListMetrics(ctx, params)
		case "cloudwatch.describe_alarms":
			return svc.DescribeAlarms(ctx, params)
		}

	case "iam":
		svc := services.NewIAMService(cfg)
		switch action {
		case "iam.get_user":
			return svc.GetUser(ctx, params)
		case "iam.list_users":
			return svc.ListUsers(ctx, params)
		case "iam.list_roles":
			return svc.ListRoles(ctx, params)
		case "iam.list_policies":
			return svc.ListPolicies(ctx, params)
		}

	case "secretsmanager":
		svc := services.NewSecretsManagerService(cfg)
		switch action {
		case "secretsmanager.get_secret_value":
			return svc.GetSecretValue(ctx, params)
		case "secretsmanager.list_secrets":
			return svc.ListSecrets(ctx, params)
		case "secretsmanager.describe_secret":
			return svc.DescribeSecret(ctx, params)
		}
	}

	return nil, fmt.Errorf("unhandled action: %s", action)
}

// --- Helper functions ---

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

// extractResourceARN derives the target resource ARN from the action and params.
// Returns "" for actions that don't target a specific resource (e.g., list operations).
func extractResourceARN(action string, params map[string]any) string {
	service := strings.SplitN(action, ".", 2)[0]

	switch service {
	case "s3":
		bucket, _ := params["bucket"].(string)
		if bucket == "" {
			return ""
		}
		if strings.HasPrefix(bucket, "arn:") {
			return bucket
		}
		return "arn:aws:s3:::" + bucket

	case "lambda":
		funcName, _ := params["function_name"].(string)
		if funcName == "" {
			return ""
		}
		if strings.HasPrefix(funcName, "arn:") {
			return funcName
		}
		return "arn:aws:lambda:*:*:function:" + funcName

	case "sqs":
		// send_message and receive_message use queue_url
		queueURL, _ := params["queue_url"].(string)
		if queueURL != "" {
			if strings.HasPrefix(queueURL, "arn:") {
				return queueURL
			}
			// Parse https://sqs.{region}.amazonaws.com/{account}/{queue-name}
			if strings.HasPrefix(queueURL, "https://sqs.") {
				parts := strings.Split(strings.TrimPrefix(queueURL, "https://"), "/")
				if len(parts) >= 3 {
					hostParts := strings.SplitN(parts[0], ".", 3)
					if len(hostParts) >= 2 {
						region := hostParts[1]
						account := parts[1]
						queueName := parts[2]
						return fmt.Sprintf("arn:aws:sqs:%s:%s:%s", region, account, queueName)
					}
				}
			}
			return queueURL
		}
		// get_queue_url uses queue_name
		queueName, _ := params["queue_name"].(string)
		if queueName != "" {
			return "arn:aws:sqs:*:*:" + queueName
		}
		return ""

	case "sns":
		topicARN, _ := params["topic_arn"].(string)
		return topicARN

	default:
		// EC2, CloudWatch, IAM, SecretsManager — no specific resource target
		return ""
	}
}
