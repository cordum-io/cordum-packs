package worker

import (
	"reflect"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/kubernetes-triage/internal/config"
)

func TestBuildKubectlArgsPodsList(t *testing.T) {
	profile := config.Profile{KubectlPath: "kubectl", Namespace: "default"}
	spec := actionSpecs["pods.list"]
	args, err := buildKubectlArgs(profile, spec, "default", map[string]any{"label_selector": "app=api"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"-n", "default", "get", "pods", "-o", "json", "-l", "app=api"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestBuildKubectlArgsScale(t *testing.T) {
	profile := config.Profile{KubectlPath: "kubectl", Namespace: "default"}
	spec := actionSpecs["deployments.scale"]
	args, err := buildKubectlArgs(profile, spec, "default", map[string]any{"name": "api", "replicas": 3})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []string{"-n", "default", "scale", "deployment/api", "--replicas", "3"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("unexpected args: %v", args)
	}
}

func TestResolveNamespace(t *testing.T) {
	profile := config.Profile{Namespace: "default"}
	if got := resolveNamespace(profile, map[string]any{"namespace": "prod"}, true); got != "prod" {
		t.Fatalf("expected namespace override, got %q", got)
	}
	if got := resolveNamespace(profile, map[string]any{}, true); got != "default" {
		t.Fatalf("expected profile namespace, got %q", got)
	}
}

func TestEnforceNamespacePolicy(t *testing.T) {
	profile := config.Profile{AllowedNamespaces: []string{"prod"}}
	if err := enforceNamespacePolicy(profile, "prod"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceNamespacePolicy(profile, "dev"); err == nil {
		t.Fatalf("expected error for disallowed namespace")
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"name": "api"}
	if err := validateParams(params, []string{"name"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(params, []string{"missing"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}
