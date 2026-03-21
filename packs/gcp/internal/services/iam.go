package services

import (
	"context"
	"fmt"
	"strings"

	iamadmin "cloud.google.com/go/iam/admin/apiv1"
	adminpb "cloud.google.com/go/iam/admin/apiv1/adminpb"
	iampb "cloud.google.com/go/iam/apiv1/iampb"
	giterator "google.golang.org/api/iterator"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

// IAMService wraps IAM read operations.
type IAMService struct {
	client    *iamadmin.IamClient
	projectID string
}

// NewIAMService creates an IAM service.
func NewIAMService(ctx context.Context, reqCfg gcpclient.RequestConfig) (*IAMService, error) {
	client, err := iamadmin.NewIamClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create iam client: %w", err)
	}
	return &IAMService{
		client:    client,
		projectID: reqCfg.ProjectID,
	}, nil
}

// Close releases any client resources.
func (s *IAMService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// GetIAMPolicy returns the IAM policy for a service account resource.
func (s *IAMService) GetIAMPolicy(ctx context.Context, params map[string]any) (any, error) {
	resource := stringParam(params, "resource")
	serviceAccount := stringParam(params, "service_account")
	if resource == "" && serviceAccount == "" {
		return nil, fmt.Errorf("resource or service_account is required")
	}
	if resource == "" {
		resource = s.serviceAccountResource(serviceAccount)
	}

	response, err := s.client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resource})
	if err != nil {
		return nil, err
	}

	return protoToAny(response.InternalProto)
}

// ListRoles lists predefined or custom roles.
func (s *IAMService) ListRoles(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	showDeleted, err := boolParam(params, "show_deleted", false)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")

	request := &adminpb.ListRolesRequest{
		Parent:      s.rolesParent(params),
		PageSize:    pageSize,
		PageToken:   pageToken,
		ShowDeleted: showDeleted,
		View:        s.roleView(params),
	}

	it := s.client.ListRolesIter(ctx, request)
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var roles []*adminpb.Role
	nextPageToken, err := pager.NextPage(&roles)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(roles)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"roles":           mapped,
		"next_page_token": nextPageToken,
	}, nil
}

// ListServiceAccounts lists service accounts in the project.
func (s *IAMService) ListServiceAccounts(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")

	it := s.client.ListServiceAccounts(ctx, &adminpb.ListServiceAccountsRequest{
		Name:      fmt.Sprintf("projects/%s", s.projectID),
		PageSize:  pageSize,
		PageToken: pageToken,
	})
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var accounts []*adminpb.ServiceAccount
	nextPageToken, err := pager.NextPage(&accounts)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(accounts)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"service_accounts": mapped,
		"next_page_token":  nextPageToken,
	}, nil
}

func (s *IAMService) serviceAccountResource(serviceAccount string) string {
	if isFullResource(serviceAccount) {
		return serviceAccount
	}
	return fmt.Sprintf("projects/%s/serviceAccounts/%s", s.projectID, serviceAccount)
}

func (s *IAMService) rolesParent(params map[string]any) string {
	if parent := stringParam(params, "parent"); parent != "" {
		return parent
	}
	if organizationID := stringParam(params, "organization_id"); organizationID != "" {
		return fmt.Sprintf("organizations/%s", organizationID)
	}
	if scope := strings.ToLower(stringParam(params, "scope")); scope == "project" {
		return fmt.Sprintf("projects/%s", s.projectID)
	}
	return ""
}

func (s *IAMService) roleView(params map[string]any) adminpb.RoleView {
	switch strings.ToUpper(stringParam(params, "view")) {
	case "FULL":
		return adminpb.RoleView_FULL
	default:
		return adminpb.RoleView_BASIC
	}
}
