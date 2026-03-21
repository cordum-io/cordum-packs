package worker

import (
	"context"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/config"
	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

func TestActionSpecs(t *testing.T) {
	expectedActions := []string{
		"functions.call", "functions.get_function", "functions.list_functions",
		"storage.get_object", "storage.upload_object", "storage.list_objects", "storage.list_buckets", "storage.delete_object",
		"pubsub.publish", "pubsub.list_topics", "pubsub.list_subscriptions", "pubsub.pull",
		"compute.list_instances", "compute.get_instance", "compute.aggregated_list_instances",
		"monitoring.list_time_series", "monitoring.list_metric_descriptors", "monitoring.list_alert_policies",
		"secretmanager.access_secret_version", "secretmanager.list_secrets", "secretmanager.get_secret",
		"iam.get_iam_policy", "iam.list_roles", "iam.list_service_accounts",
	}

	for _, action := range expectedActions {
		if _, ok := actionSpecs[action]; !ok {
			t.Errorf("missing action spec: %s", action)
		}
	}

	if len(actionSpecs) != len(expectedActions) {
		t.Fatalf("expected %d action specs, got %d", len(expectedActions), len(actionSpecs))
	}
}

func TestActionIntentClassification(t *testing.T) {
	readActions := []string{
		"functions.get_function", "functions.list_functions",
		"storage.get_object", "storage.list_objects", "storage.list_buckets",
		"pubsub.list_topics", "pubsub.list_subscriptions", "pubsub.pull",
		"compute.list_instances", "compute.get_instance", "compute.aggregated_list_instances",
		"monitoring.list_time_series", "monitoring.list_metric_descriptors", "monitoring.list_alert_policies",
		"secretmanager.access_secret_version", "secretmanager.list_secrets", "secretmanager.get_secret",
		"iam.get_iam_policy", "iam.list_roles", "iam.list_service_accounts",
	}
	writeActions := []string{"functions.call", "storage.upload_object", "storage.delete_object", "pubsub.publish"}

	for _, action := range readActions {
		if actionSpecs[action].Intent != "read" {
			t.Errorf("expected %s to be read intent, got %s", action, actionSpecs[action].Intent)
		}
	}
	for _, action := range writeActions {
		if actionSpecs[action].Intent != "write" {
			t.Errorf("expected %s to be write intent, got %s", action, actionSpecs[action].Intent)
		}
	}
}

func TestNormalizePayload(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		result := normalizePayload(nil)
		if result == nil {
			t.Fatal("expected non-nil payload")
		}
	})

	t.Run("extracts_context", func(t *testing.T) {
		payload := map[string]any{
			"context": map[string]any{"action": "storage.get_object"},
		}
		result := normalizePayload(payload)
		if result["action"] != "storage.get_object" {
			t.Fatalf("expected normalized action, got %v", result["action"])
		}
	})
}

func TestDecodePayload(t *testing.T) {
	payload := map[string]any{
		"profile":    "prod",
		"action":     "storage.get_object",
		"project_id": "demo-project",
		"location":   "us-central1",
		"params":     map[string]any{"bucket": "docs"},
		"request_id": "req-123",
	}

	var input JobInput
	if err := decodePayload(payload, &input); err != nil {
		t.Fatalf("decodePayload returned error: %v", err)
	}
	if input.Profile != "prod" || input.Action != "storage.get_object" || input.ProjectID != "demo-project" || input.Location != "us-central1" || input.RequestID != "req-123" {
		t.Fatalf("unexpected decoded payload: %+v", input)
	}
}

func TestResolveWorkerID(t *testing.T) {
	if got := resolveWorkerID("gcp-explicit", "gcp"); got != "gcp-explicit" {
		t.Fatalf("expected explicit worker id, got %q", got)
	}
}

func TestProfileActionValidation(t *testing.T) {
	profile := config.Profile{
		Name:         "restricted",
		AllowActions: []string{"storage.*", "functions.call"},
		DenyActions:  []string{"storage.delete_object"},
	}

	if !profile.IsActionAllowed("storage.get_object") {
		t.Fatal("expected storage.get_object to be allowed")
	}
	if !profile.IsActionAllowed("functions.call") {
		t.Fatal("expected functions.call to be allowed")
	}
	if profile.IsActionAllowed("storage.delete_object") {
		t.Fatal("expected storage.delete_object to be denied")
	}
	if profile.IsActionAllowed("iam.list_roles") {
		t.Fatal("expected iam.list_roles to be denied")
	}
}

func TestDispatchActionUnhandled(t *testing.T) {
	_, err := dispatchAction(context.Background(), gcpclient.RequestConfig{}, "unknown.action", actionSpec{Service: "unknown"}, map[string]any{})
	if err == nil || err.Error() != "unhandled action: unknown.action" {
		t.Fatalf("expected unhandled action error, got %v", err)
	}
}
