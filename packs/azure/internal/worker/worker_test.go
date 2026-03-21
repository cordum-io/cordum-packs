package worker

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/azure/internal/config"
)

func TestActionSpecs(t *testing.T) {
	expected := []string{
		"functions.invoke", "functions.list_apps",
		"blob.get", "blob.upload", "blob.list", "blob.list_containers", "blob.delete",
		"servicebus.send", "servicebus.peek",
		"compute.list_vms", "compute.get_vm", "compute.get_vm_instance_view",
		"monitor.query_metrics", "monitor.list_alert_rules",
		"keyvault.get_secret", "keyvault.list_secrets",
		"entra.get_user", "entra.list_users", "entra.list_groups",
	}
	for _, action := range expected {
		if _, ok := actionSpecs[action]; !ok {
			t.Errorf("missing action spec: %s", action)
		}
	}
	if len(actionSpecs) != len(expected) {
		t.Errorf("expected %d action specs, got %d", len(expected), len(actionSpecs))
	}
}

func TestActionIntentClassification(t *testing.T) {
	writeActions := []string{"functions.invoke", "blob.upload", "blob.delete", "servicebus.send"}
	for _, action := range writeActions {
		if actionSpecs[action].Intent != "write" {
			t.Errorf("expected %s to be write", action)
		}
	}

	readActions := []string{"blob.get", "compute.list_vms", "keyvault.get_secret", "entra.list_users"}
	for _, action := range readActions {
		if actionSpecs[action].Intent != "read" {
			t.Errorf("expected %s to be read", action)
		}
	}
}

func TestNormalizePayload(t *testing.T) {
	result := normalizePayload(nil)
	if result == nil {
		t.Fatal("expected non-nil")
	}

	result = normalizePayload(map[string]any{"context": map[string]any{"action": "blob.get"}})
	if result["action"] != "blob.get" {
		t.Errorf("expected action=blob.get, got %v", result["action"])
	}
}

func TestDecodePayload(t *testing.T) {
	var input JobInput
	err := decodePayload(map[string]any{"action": "blob.get", "profile": "prod"}, &input)
	if err != nil {
		t.Fatal(err)
	}
	if input.Action != "blob.get" {
		t.Errorf("expected blob.get, got %q", input.Action)
	}
}

func TestProfileActionValidation(t *testing.T) {
	profile := config.Profile{AllowActions: []string{"blob.*", "keyvault.*"}}
	if !profile.IsActionAllowed("blob.get") {
		t.Error("expected blob.get allowed")
	}
	if profile.IsActionAllowed("compute.list_vms") {
		t.Error("expected compute.list_vms denied")
	}
}

func TestServiceMapping(t *testing.T) {
	mapping := map[string]string{
		"functions.invoke": "functions",
		"blob.get":         "blob",
		"servicebus.send":  "servicebus",
		"compute.list_vms": "compute",
		"monitor.query_metrics": "monitor",
		"keyvault.get_secret":   "keyvault",
		"entra.get_user":        "entra",
	}
	for action, expectedService := range mapping {
		if actionSpecs[action].Service != expectedService {
			t.Errorf("action %s: expected service %q, got %q", action, expectedService, actionSpecs[action].Service)
		}
	}
}
