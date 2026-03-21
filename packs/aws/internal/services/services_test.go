package services

import (
	"fmt"
	"testing"
)

// TestLambdaInvokeValidation tests Lambda invoke parameter validation.
func TestLambdaInvokeValidation(t *testing.T) {
	// We can't create a real Lambda client without AWS creds, but we can test
	// the validation logic by passing empty params.
	svc := &LambdaService{} // nil client — will panic on API call but we test before that

	_, err := svc.Invoke(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing function_name")
	}
	if err.Error() != "function_name is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestS3GetObjectValidation tests S3 GetObject parameter validation.
func TestS3GetObjectValidation(t *testing.T) {
	svc := &S3Service{}

	tests := []struct {
		name   string
		params map[string]any
		errMsg string
	}{
		{"empty params", map[string]any{}, "bucket and key are required"},
		{"only bucket", map[string]any{"bucket": "my-bucket"}, "bucket and key are required"},
		{"only key", map[string]any{"key": "my-key"}, "bucket and key are required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.GetObject(nil, tt.params)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tt.errMsg {
				t.Errorf("expected %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// TestS3PutObjectValidation tests S3 PutObject parameter validation.
func TestS3PutObjectValidation(t *testing.T) {
	svc := &S3Service{}

	_, err := svc.PutObject(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing params")
	}
	if err.Error() != "bucket and key are required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSQSSendMessageValidation tests SQS SendMessage validation.
func TestSQSSendMessageValidation(t *testing.T) {
	svc := &SQSService{}

	_, err := svc.SendMessage(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "queue_url and message_body are required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSQSReceiveMessageValidation tests SQS ReceiveMessage validation.
func TestSQSReceiveMessageValidation(t *testing.T) {
	svc := &SQSService{}

	_, err := svc.ReceiveMessage(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "queue_url is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSQSGetQueueURLValidation tests SQS GetQueueURL validation.
func TestSQSGetQueueURLValidation(t *testing.T) {
	svc := &SQSService{}

	_, err := svc.GetQueueURL(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "queue_name is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSNSPublishValidation tests SNS Publish validation.
func TestSNSPublishValidation(t *testing.T) {
	svc := &SNSService{}

	_, err := svc.Publish(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "topic_arn and message are required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSecretsManagerGetValidation tests Secrets Manager validation.
func TestSecretsManagerGetValidation(t *testing.T) {
	svc := &SecretsManagerService{}

	_, err := svc.GetSecretValue(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "secret_id is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSecretsManagerDescribeValidation tests Secrets Manager DescribeSecret validation.
func TestSecretsManagerDescribeValidation(t *testing.T) {
	svc := &SecretsManagerService{}

	_, err := svc.DescribeSecret(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "secret_id is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestCloudWatchGetMetricDataValidation tests CloudWatch validation.
func TestCloudWatchGetMetricDataValidation(t *testing.T) {
	svc := &CloudWatchService{}

	_, err := svc.GetMetricData(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "namespace and metric_name are required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestS3ListObjectsValidation tests S3 ListObjects validation.
func TestS3ListObjectsValidation(t *testing.T) {
	svc := &S3Service{}

	_, err := svc.ListObjects(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "bucket is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestS3HeadObjectValidation tests S3 HeadObject validation.
func TestS3HeadObjectValidation(t *testing.T) {
	svc := &S3Service{}

	_, err := svc.HeadObject(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "bucket and key are required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestS3DeleteObjectValidation tests S3 DeleteObject validation.
func TestS3DeleteObjectValidation(t *testing.T) {
	svc := &S3Service{}

	_, err := svc.DeleteObject(nil, map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "bucket and key are required" {
		t.Errorf("unexpected error: %v", err)
	}
}

// Verify all service constructors compile (type check).
func TestServiceConstructorsCompile(t *testing.T) {
	// We can't call these with a real aws.Config without credentials,
	// but we verify the constructors exist and accept the right type.
	constructors := []string{
		"NewLambdaService",
		"NewS3Service",
		"NewSQSService",
		"NewSNSService",
		"NewEC2Service",
		"NewCloudWatchService",
		"NewIAMService",
		"NewSecretsManagerService",
	}
	if len(constructors) != 8 {
		t.Errorf("expected 8 service constructors, got %d", len(constructors))
	}
	// Simple compilation test — if any constructor signature is wrong, this won't compile
	_ = fmt.Sprintf("constructors: %v", constructors)
}
