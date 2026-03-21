package services

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretsManagerService wraps AWS Secrets Manager operations.
type SecretsManagerService struct {
	client *secretsmanager.Client
}

// NewSecretsManagerService creates a Secrets Manager service from an AWS config.
func NewSecretsManagerService(cfg aws.Config) *SecretsManagerService {
	return &SecretsManagerService{client: secretsmanager.NewFromConfig(cfg)}
}

// GetSecretValue retrieves a secret value.
func (s *SecretsManagerService) GetSecretValue(ctx context.Context, params map[string]any) (any, error) {
	secretID, _ := params["secret_id"].(string)
	if secretID == "" {
		return nil, fmt.Errorf("secret_id is required")
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}
	if versionID, ok := params["version_id"].(string); ok && versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	if versionStage, ok := params["version_stage"].(string); ok && versionStage != "" {
		input.VersionStage = aws.String(versionStage)
	}

	out, err := s.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, err
	}

	result := map[string]any{
		"name":       aws.ToString(out.Name),
		"arn":        aws.ToString(out.ARN),
		"version_id": aws.ToString(out.VersionId),
	}
	if out.SecretString != nil {
		result["secret_string"] = *out.SecretString
	}

	return result, nil
}

// ListSecrets lists secrets in the account.
func (s *SecretsManagerService) ListSecrets(ctx context.Context, params map[string]any) (any, error) {
	input := &secretsmanager.ListSecretsInput{}
	if maxResults, ok := params["max_results"].(float64); ok && maxResults > 0 {
		input.MaxResults = aws.Int32(int32(maxResults))
	}

	out, err := s.client.ListSecrets(ctx, input)
	if err != nil {
		return nil, err
	}

	secrets := make([]map[string]any, 0, len(out.SecretList))
	for _, secret := range out.SecretList {
		secrets = append(secrets, map[string]any{
			"name": aws.ToString(secret.Name),
			"arn":  aws.ToString(secret.ARN),
		})
	}
	return map[string]any{"secrets": secrets, "count": len(secrets)}, nil
}

// DescribeSecret returns metadata about a secret.
func (s *SecretsManagerService) DescribeSecret(ctx context.Context, params map[string]any) (any, error) {
	secretID, _ := params["secret_id"].(string)
	if secretID == "" {
		return nil, fmt.Errorf("secret_id is required")
	}

	out, err := s.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretID),
	})
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"name":          aws.ToString(out.Name),
		"arn":           aws.ToString(out.ARN),
		"description":   aws.ToString(out.Description),
		"last_changed":  out.LastChangedDate,
		"last_accessed": out.LastAccessedDate,
	}, nil
}
