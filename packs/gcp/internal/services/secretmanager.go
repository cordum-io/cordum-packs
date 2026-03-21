package services

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	giterator "google.golang.org/api/iterator"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

// SecretManagerService wraps Secret Manager operations.
type SecretManagerService struct {
	client    *secretmanager.Client
	projectID string
	location  string
}

// NewSecretManagerService creates a Secret Manager service.
func NewSecretManagerService(ctx context.Context, reqCfg gcpclient.RequestConfig) (*SecretManagerService, error) {
	client, err := secretmanager.NewClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create secret manager client: %w", err)
	}
	return &SecretManagerService{
		client:    client,
		projectID: reqCfg.ProjectID,
		location:  reqCfg.Location,
	}, nil
}

// Close releases any client resources.
func (s *SecretManagerService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// AccessSecretVersion returns a secret version payload.
func (s *SecretManagerService) AccessSecretVersion(ctx context.Context, params map[string]any) (any, error) {
	secretID := stringParam(params, "secret_id")
	if secretID == "" {
		return nil, fmt.Errorf("secret_id is required")
	}

	version := stringParam(params, "version")
	if version == "" {
		version = "latest"
	}

	response, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: s.secretVersionResource(secretID, version),
	})
	if err != nil {
		return nil, err
	}

	return protoToAny(response)
}

// ListSecrets lists secrets in the project.
func (s *SecretManagerService) ListSecrets(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}
	pageToken := stringParam(params, "page_token")

	it := s.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent:    s.secretParent(),
		Filter:    stringParam(params, "filter"),
		PageSize:  pageSize,
		PageToken: pageToken,
	})
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var secrets []*secretmanagerpb.Secret
	nextPageToken, err := pager.NextPage(&secrets)
	if err != nil {
		return nil, err
	}

	mapped, err := protoSliceToMaps(secrets)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"secrets":         mapped,
		"next_page_token": nextPageToken,
	}, nil
}

// GetSecret returns a secret definition.
func (s *SecretManagerService) GetSecret(ctx context.Context, params map[string]any) (any, error) {
	secretID := stringParam(params, "secret_id")
	if secretID == "" {
		return nil, fmt.Errorf("secret_id is required")
	}

	response, err := s.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{
		Name: s.secretResource(secretID),
	})
	if err != nil {
		return nil, err
	}

	return protoToAny(response)
}

func (s *SecretManagerService) secretParent() string {
	location := strings.TrimSpace(s.location)
	if location == "" || strings.EqualFold(location, "global") {
		return fmt.Sprintf("projects/%s", s.projectID)
	}
	return fmt.Sprintf("projects/%s/locations/%s", s.projectID, location)
}

func (s *SecretManagerService) secretResource(secretID string) string {
	if isFullResource(secretID) {
		return secretID
	}
	return fmt.Sprintf("%s/secrets/%s", s.secretParent(), secretID)
}

func (s *SecretManagerService) secretVersionResource(secretID, version string) string {
	if strings.Contains(secretID, "/versions/") {
		return secretID
	}
	return fmt.Sprintf("%s/versions/%s", s.secretResource(secretID), version)
}
