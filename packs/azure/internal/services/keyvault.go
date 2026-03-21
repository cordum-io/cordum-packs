package services

import (
	"context"
	"fmt"
)

// KeyVaultService wraps Azure Key Vault operations.
type KeyVaultService struct {
	client *AzureClient
}

// NewKeyVaultService creates a Key Vault service.
func NewKeyVaultService(client *AzureClient) *KeyVaultService {
	return &KeyVaultService{client: client}
}

// GetSecret retrieves a secret from Key Vault.
func (s *KeyVaultService) GetSecret(ctx context.Context, params map[string]any) (any, error) {
	vaultName, _ := params["vault_name"].(string)
	secretName, _ := params["secret_name"].(string)
	if vaultName == "" || secretName == "" {
		return nil, fmt.Errorf("vault_name and secret_name are required")
	}

	version, _ := params["version"].(string)
	url := KeyVaultURL(vaultName, secretName, version)

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "https://vault.azure.net/.default", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListSecrets lists secrets in a Key Vault.
func (s *KeyVaultService) ListSecrets(ctx context.Context, params map[string]any) (any, error) {
	vaultName, _ := params["vault_name"].(string)
	if vaultName == "" {
		return nil, fmt.Errorf("vault_name is required")
	}

	url := fmt.Sprintf("https://%s.vault.azure.net/secrets?api-version=7.4", vaultName)
	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "https://vault.azure.net/.default", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}
