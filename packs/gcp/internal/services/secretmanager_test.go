package services

import (
	"context"
	"testing"
)

func TestSecretManagerAccessSecretVersionValidation(t *testing.T) {
	t.Parallel()

	svc := &SecretManagerService{}
	_, err := svc.AccessSecretVersion(context.Background(), map[string]any{})
	assertErrMsg(t, err, "secret_id is required")
}

func TestSecretManagerGetSecretValidation(t *testing.T) {
	t.Parallel()

	svc := &SecretManagerService{}
	_, err := svc.GetSecret(context.Background(), map[string]any{})
	assertErrMsg(t, err, "secret_id is required")
}

func TestSecretManagerHelpers(t *testing.T) {
	t.Parallel()

	globalSvc := &SecretManagerService{projectID: "demo-project", location: "global"}
	if got, want := globalSvc.secretParent(), "projects/demo-project"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}

	regionalSvc := &SecretManagerService{projectID: "demo-project", location: "us-central1"}
	if got, want := regionalSvc.secretParent(), "projects/demo-project/locations/us-central1"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got, want := regionalSvc.secretResource("api-key"), "projects/demo-project/locations/us-central1/secrets/api-key"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got, want := regionalSvc.secretVersionResource("api-key", "5"), "projects/demo-project/locations/us-central1/secrets/api-key/versions/5"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
