package services

import (
	"context"
	"testing"

	adminpb "cloud.google.com/go/iam/admin/apiv1/adminpb"
)

func TestIAMGetPolicyValidation(t *testing.T) {
	t.Parallel()

	svc := &IAMService{}
	_, err := svc.GetIAMPolicy(context.Background(), map[string]any{})
	assertErrMsg(t, err, "resource or service_account is required")
}

func TestIAMListRolesValidation(t *testing.T) {
	t.Parallel()

	svc := &IAMService{}
	_, err := svc.ListRoles(context.Background(), map[string]any{"show_deleted": "sometimes"})
	assertErrContains(t, err, "show_deleted must be boolean")
}

func TestIAMListServiceAccountsValidation(t *testing.T) {
	t.Parallel()

	svc := &IAMService{}
	_, err := svc.ListServiceAccounts(context.Background(), map[string]any{"page_size": "oops"})
	assertErrContains(t, err, "page_size must be an integer")
}

func TestIAMHelpers(t *testing.T) {
	t.Parallel()

	svc := &IAMService{projectID: "demo-project"}

	if got, want := svc.serviceAccountResource("runner@demo-project.iam.gserviceaccount.com"), "projects/demo-project/serviceAccounts/runner@demo-project.iam.gserviceaccount.com"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got, want := svc.rolesParent(map[string]any{"scope": "project"}), "projects/demo-project"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got, want := svc.rolesParent(map[string]any{"organization_id": "123456789"}), "organizations/123456789"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got := svc.roleView(map[string]any{"view": "FULL"}); got != adminpb.RoleView_FULL {
		t.Fatalf("expected FULL role view, got %v", got)
	}
	if got := svc.roleView(nil); got != adminpb.RoleView_BASIC {
		t.Fatalf("expected BASIC role view, got %v", got)
	}
}
