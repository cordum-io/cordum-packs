package azureclient

import (
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/cordum-io/cordum-packs/packs/azure/internal/config"
)

// NewCredential creates an Azure credential from the given profile.
//
// Two paths:
//   - Explicit credentials: if TenantID, ClientID, and ClientSecret are all present,
//     uses azidentity.NewClientSecretCredential directly. This is goroutine-safe
//     (no process-level env mutation).
//   - Ambient auth: otherwise falls back to azidentity.NewDefaultAzureCredential,
//     which probes env vars, managed identity, Azure CLI, etc.
func NewCredential(profile config.Profile) (azcore.TokenCredential, error) {
	secret := profile.ResolveClientSecret()
	if profile.TenantID != "" && profile.ClientID != "" && secret != "" {
		cred, err := azidentity.NewClientSecretCredential(profile.TenantID, profile.ClientID, secret, nil)
		if err != nil {
			return nil, fmt.Errorf("create client secret credential: %w", err)
		}
		return cred, nil
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create default credential: %w", err)
	}
	return cred, nil
}

// ResolveSubscriptionID returns the effective subscription ID.
func ResolveSubscriptionID(override string, profile config.Profile) string {
	if override != "" {
		return override
	}
	if profile.SubscriptionID != "" {
		return profile.SubscriptionID
	}
	return strings.TrimSpace(os.Getenv("AZURE_SUBSCRIPTION_ID"))
}

// ResolveResourceGroup returns the effective resource group.
func ResolveResourceGroup(override string, profile config.Profile) string {
	if override != "" {
		return override
	}
	return profile.ResourceGroup
}
