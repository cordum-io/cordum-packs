// Package services implements Azure service operations using REST API calls
// authenticated via azidentity tokens. This avoids pulling in per-service SDK
// modules (which are large and often in beta) while maintaining full functionality.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// AzureClient wraps HTTP requests with Azure AD token authentication.
type AzureClient struct {
	credential azcore.TokenCredential
	httpClient *http.Client
}

// NewAzureClient creates a new Azure REST client.
func NewAzureClient(credential azcore.TokenCredential) *AzureClient {
	return &AzureClient{
		credential: credential,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// DoRawRequest makes an authenticated Azure REST API request and returns the
// raw *http.Response. The caller is responsible for closing resp.Body.
// Custom headers override defaults; if no Content-Type is provided in headers,
// it defaults to application/json.
func (c *AzureClient) DoRawRequest(ctx context.Context, method, url string, body io.Reader, scope string, headers map[string]string) (*http.Response, error) {
	if scope == "" {
		scope = "https://management.azure.com/.default"
	}

	token, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{scope},
	})
	if err != nil {
		return nil, fmt.Errorf("get azure token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)

	// Apply custom headers; default Content-Type to JSON if not specified
	hasContentType := false
	for k, v := range headers {
		req.Header.Set(k, v)
		if strings.EqualFold(k, "Content-Type") {
			hasContentType = true
		}
	}
	if !hasContentType {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	return resp, nil
}

// DoRequest makes an authenticated Azure REST API request and returns the
// parsed JSON response. Pass nil for headers to use default Content-Type.
func (c *AzureClient) DoRequest(ctx context.Context, method, url string, body io.Reader, scope string, headers map[string]string) (map[string]any, int, error) {
	resp, err := c.DoRawRequest(ctx, method, url, body, scope, headers)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, resp.StatusCode, fmt.Errorf("azure API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if len(respBody) > 0 {
		if err := json.Unmarshal(respBody, &result); err != nil {
			// Some responses are plain text
			return map[string]any{"body": string(respBody)}, resp.StatusCode, nil
		}
	}

	return result, resp.StatusCode, nil
}

// ManagementURL builds an Azure Resource Manager URL.
func ManagementURL(subscriptionID, path string) string {
	base := "https://management.azure.com"
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return fmt.Sprintf("%s/subscriptions/%s/%s", base, subscriptionID, path)
}

// BlobURL builds an Azure Blob Storage URL.
func BlobURL(storageAccount, container, blobName string) string {
	return fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", storageAccount, container, blobName)
}

// KeyVaultURL builds a Key Vault secret URL.
func KeyVaultURL(vaultName, secretName, version string) string {
	base := fmt.Sprintf("https://%s.vault.azure.net/secrets/%s", vaultName, secretName)
	if version != "" {
		base += "/" + version
	}
	return base + "?api-version=7.4"
}
