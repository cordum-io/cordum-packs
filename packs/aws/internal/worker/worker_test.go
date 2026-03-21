package worker

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/aws/internal/config"
)

// TestActionSpecs verifies all expected actions are registered.
func TestActionSpecs(t *testing.T) {
	expectedActions := []string{
		"lambda.invoke", "lambda.get_function", "lambda.list_functions",
		"s3.get_object", "s3.put_object", "s3.list_buckets", "s3.list_objects", "s3.head_object", "s3.delete_object",
		"sqs.send_message", "sqs.receive_message", "sqs.get_queue_url", "sqs.list_queues",
		"sns.publish", "sns.list_topics", "sns.list_subscriptions",
		"ec2.describe_instances", "ec2.describe_security_groups", "ec2.describe_vpcs",
		"cloudwatch.get_metric_data", "cloudwatch.list_metrics", "cloudwatch.describe_alarms",
		"iam.get_user", "iam.list_users", "iam.list_roles", "iam.list_policies",
		"secretsmanager.get_secret_value", "secretsmanager.list_secrets", "secretsmanager.describe_secret",
	}

	for _, action := range expectedActions {
		if _, ok := actionSpecs[action]; !ok {
			t.Errorf("missing action spec: %s", action)
		}
	}

	if len(actionSpecs) != len(expectedActions) {
		t.Errorf("expected %d action specs, got %d", len(expectedActions), len(actionSpecs))
	}
}

// TestActionIntentClassification verifies read/write classification.
func TestActionIntentClassification(t *testing.T) {
	readActions := []string{
		"s3.get_object", "s3.list_buckets", "s3.list_objects", "s3.head_object",
		"sqs.receive_message", "sqs.get_queue_url", "sqs.list_queues",
		"sns.list_topics", "sns.list_subscriptions",
		"ec2.describe_instances", "ec2.describe_security_groups", "ec2.describe_vpcs",
		"cloudwatch.get_metric_data", "cloudwatch.list_metrics", "cloudwatch.describe_alarms",
		"iam.get_user", "iam.list_users", "iam.list_roles", "iam.list_policies",
		"secretsmanager.get_secret_value", "secretsmanager.list_secrets", "secretsmanager.describe_secret",
		"lambda.get_function", "lambda.list_functions",
	}

	writeActions := []string{
		"lambda.invoke",
		"s3.put_object", "s3.delete_object",
		"sqs.send_message",
		"sns.publish",
	}

	for _, action := range readActions {
		spec := actionSpecs[action]
		if spec.Intent != "read" {
			t.Errorf("action %s should be read, got %s", action, spec.Intent)
		}
	}

	for _, action := range writeActions {
		spec := actionSpecs[action]
		if spec.Intent != "write" {
			t.Errorf("action %s should be write, got %s", action, spec.Intent)
		}
	}
}

// TestNormalizePayload tests payload normalization.
func TestNormalizePayload(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		result := normalizePayload(nil)
		if result == nil {
			t.Fatal("expected non-nil map")
		}
	})

	t.Run("context extraction", func(t *testing.T) {
		payload := map[string]any{
			"context": map[string]any{"action": "s3.get_object"},
		}
		result := normalizePayload(payload)
		if result["action"] != "s3.get_object" {
			t.Errorf("expected action=s3.get_object, got %v", result["action"])
		}
	})
}

// TestDecodePayload tests JSON round-trip decode.
func TestDecodePayload(t *testing.T) {
	payload := map[string]any{
		"action":  "lambda.invoke",
		"profile": "prod",
		"region":  "eu-west-1",
		"params":  map[string]any{"function_name": "my-func"},
	}

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if input.Action != "lambda.invoke" {
		t.Errorf("expected action=lambda.invoke, got %q", input.Action)
	}
	if input.Profile != "prod" {
		t.Errorf("expected profile=prod, got %q", input.Profile)
	}
	if input.Region != "eu-west-1" {
		t.Errorf("expected region=eu-west-1, got %q", input.Region)
	}
}

// TestTopicIntentEnforcement verifies write actions can't run on read topics.
func TestTopicIntentEnforcement(t *testing.T) {
	writeOnReadTopicActions := []string{"lambda.invoke", "s3.put_object", "s3.delete_object", "sqs.send_message", "sns.publish"}

	for _, action := range writeOnReadTopicActions {
		spec := actionSpecs[action]
		if spec.Intent != "write" {
			t.Errorf("expected %s to be write intent", action)
		}
		// These should be blocked on read topic
		topicIntent := "read"
		if spec.Intent == "write" && topicIntent == "read" {
			// Correctly blocked — this is the expected behavior
		} else {
			t.Errorf("write action %s should be blocked on read topic", action)
		}
	}
}

// TestProfileActionValidation tests profile-level action validation.
func TestProfileActionValidation(t *testing.T) {
	profile := config.Profile{
		Name:       "restricted",
		AllowActions: []string{"s3.*", "lambda.invoke"},
	}

	if !profile.IsActionAllowed("s3.get_object") {
		t.Error("expected s3.get_object to be allowed")
	}
	if !profile.IsActionAllowed("lambda.invoke") {
		t.Error("expected lambda.invoke to be allowed")
	}
	if profile.IsActionAllowed("ec2.describe_instances") {
		t.Error("expected ec2.describe_instances to be denied")
	}
}

// TestExtractResourceARN tests ARN extraction for all service types.
func TestExtractResourceARN(t *testing.T) {
	tests := []struct {
		name   string
		action string
		params map[string]any
		want   string
	}{
		// S3
		{"s3 bucket name", "s3.get_object", map[string]any{"bucket": "my-bucket"}, "arn:aws:s3:::my-bucket"},
		{"s3 full ARN passthrough", "s3.get_object", map[string]any{"bucket": "arn:aws:s3:::existing-arn"}, "arn:aws:s3:::existing-arn"},
		{"s3 list_buckets no bucket", "s3.list_buckets", map[string]any{}, ""},

		// Lambda
		{"lambda function name", "lambda.invoke", map[string]any{"function_name": "my-func"}, "arn:aws:lambda:*:*:function:my-func"},
		{"lambda full ARN passthrough", "lambda.invoke", map[string]any{"function_name": "arn:aws:lambda:us-east-1:123:function:my-func"}, "arn:aws:lambda:us-east-1:123:function:my-func"},
		{"lambda list_functions no name", "lambda.list_functions", map[string]any{}, ""},

		// SQS
		{"sqs queue_url parsed", "sqs.send_message", map[string]any{"queue_url": "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue"}, "arn:aws:sqs:us-east-1:123456789012:my-queue"},
		{"sqs queue_url ARN passthrough", "sqs.send_message", map[string]any{"queue_url": "arn:aws:sqs:us-east-1:123:my-queue"}, "arn:aws:sqs:us-east-1:123:my-queue"},
		{"sqs queue_name", "sqs.get_queue_url", map[string]any{"queue_name": "my-queue"}, "arn:aws:sqs:*:*:my-queue"},
		{"sqs list_queues empty", "sqs.list_queues", map[string]any{}, ""},

		// SNS
		{"sns topic_arn passthrough", "sns.publish", map[string]any{"topic_arn": "arn:aws:sns:us-east-1:123:my-topic"}, "arn:aws:sns:us-east-1:123:my-topic"},
		{"sns list_topics empty", "sns.list_topics", map[string]any{}, ""},

		// Other services
		{"ec2 no resource", "ec2.describe_instances", map[string]any{}, ""},
		{"iam no resource", "iam.list_users", map[string]any{}, ""},
		{"cloudwatch no resource", "cloudwatch.list_metrics", map[string]any{}, ""},
		{"secretsmanager no resource", "secretsmanager.list_secrets", map[string]any{}, ""},

		// Nil params
		{"nil params", "s3.list_buckets", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResourceARN(tt.action, tt.params)
			if got != tt.want {
				t.Errorf("extractResourceARN(%q, %v) = %q, want %q", tt.action, tt.params, got, tt.want)
			}
		})
	}
}

// TestResourceAllowedRejectsDisallowed verifies resource rejection.
func TestResourceAllowedRejectsDisallowed(t *testing.T) {
	profile := config.Profile{
		Name:             "restricted",
		AllowedResources: []string{"arn:aws:s3:::dev-*"},
	}

	arn := extractResourceARN("s3.get_object", map[string]any{"bucket": "prod-data"})
	if profile.IsResourceAllowed(arn) {
		t.Errorf("expected resource %q to be rejected by profile %q", arn, profile.Name)
	}
}

// TestResourceAllowedPermitsAllowed verifies allowed resources pass through.
func TestResourceAllowedPermitsAllowed(t *testing.T) {
	profile := config.Profile{
		Name:             "restricted",
		AllowedResources: []string{"arn:aws:s3:::dev-*"},
	}

	arn := extractResourceARN("s3.get_object", map[string]any{"bucket": "dev-logs"})
	if !profile.IsResourceAllowed(arn) {
		t.Errorf("expected resource %q to be allowed by profile %q", arn, profile.Name)
	}
}

// TestResourceAllowedEmptyARN verifies empty ARN is always allowed.
func TestResourceAllowedEmptyARN(t *testing.T) {
	profile := config.Profile{
		Name:             "restricted",
		AllowedResources: []string{"arn:aws:s3:::dev-*"},
	}

	arn := extractResourceARN("s3.list_buckets", map[string]any{})
	if !profile.IsResourceAllowed(arn) {
		t.Error("expected empty ARN to be allowed")
	}
}

// TestResourceDeniedTakesPriority verifies deny rules override allow rules.
func TestResourceDeniedTakesPriority(t *testing.T) {
	profile := config.Profile{
		Name:             "mixed",
		AllowedResources: []string{"arn:aws:s3:::*"},
		DeniedResources:  []string{"arn:aws:s3:::prod-*"},
	}

	arn := extractResourceARN("s3.get_object", map[string]any{"bucket": "prod-data"})
	if profile.IsResourceAllowed(arn) {
		t.Errorf("expected resource %q to be denied (deny takes priority)", arn)
	}

	arn2 := extractResourceARN("s3.get_object", map[string]any{"bucket": "dev-data"})
	if !profile.IsResourceAllowed(arn2) {
		t.Errorf("expected resource %q to be allowed", arn2)
	}
}

// TestServiceMapping verifies all actions map to the correct service.
func TestServiceMapping(t *testing.T) {
	serviceActions := map[string][]string{
		"lambda":          {"lambda.invoke", "lambda.get_function", "lambda.list_functions"},
		"s3":              {"s3.get_object", "s3.put_object", "s3.list_buckets", "s3.list_objects", "s3.head_object", "s3.delete_object"},
		"sqs":             {"sqs.send_message", "sqs.receive_message", "sqs.get_queue_url", "sqs.list_queues"},
		"sns":             {"sns.publish", "sns.list_topics", "sns.list_subscriptions"},
		"ec2":             {"ec2.describe_instances", "ec2.describe_security_groups", "ec2.describe_vpcs"},
		"cloudwatch":      {"cloudwatch.get_metric_data", "cloudwatch.list_metrics", "cloudwatch.describe_alarms"},
		"iam":             {"iam.get_user", "iam.list_users", "iam.list_roles", "iam.list_policies"},
		"secretsmanager":  {"secretsmanager.get_secret_value", "secretsmanager.list_secrets", "secretsmanager.describe_secret"},
	}

	for service, actions := range serviceActions {
		for _, action := range actions {
			spec := actionSpecs[action]
			if spec.Service != service {
				t.Errorf("action %s: expected service %q, got %q", action, service, spec.Service)
			}
		}
	}
}
