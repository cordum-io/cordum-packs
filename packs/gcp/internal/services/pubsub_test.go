package services

import (
	"context"
	"testing"
)

func TestPubSubPublishValidation(t *testing.T) {
	t.Parallel()

	svc := &PubSubService{}
	_, err := svc.Publish(context.Background(), map[string]any{})
	assertErrMsg(t, err, "topic and data are required")
}

func TestPubSubPublishRejectsUnsupportedEncoding(t *testing.T) {
	t.Parallel()

	svc := &PubSubService{}
	_, err := svc.Publish(context.Background(), map[string]any{
		"topic":         "events",
		"data":          "hello",
		"data_encoding": "gzip",
	})
	assertErrMsg(t, err, `unsupported data encoding "gzip"`)
}

func TestPubSubPullValidation(t *testing.T) {
	t.Parallel()

	svc := &PubSubService{}
	_, err := svc.Pull(context.Background(), map[string]any{})
	assertErrMsg(t, err, "subscription is required")
}

func TestPubSubResourceBuilders(t *testing.T) {
	t.Parallel()

	svc := &PubSubService{projectID: "demo-project"}

	if got, want := svc.projectResource(), "projects/demo-project"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got, want := svc.topicResource("events"), "projects/demo-project/topics/events"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got, want := svc.subscriptionResource("worker-sub"), "projects/demo-project/subscriptions/worker-sub"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
