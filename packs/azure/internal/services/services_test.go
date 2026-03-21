package services

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// mockCredential implements azcore.TokenCredential for testing.
type mockCredential struct{}

func (m *mockCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "mock-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestFunctionsInvokeValidation(t *testing.T) {
	svc := &FunctionsService{}
	_, err := svc.InvokeFunction(nil, map[string]any{})
	if err == nil || err.Error() != "function_app and function_name are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestFunctionsListAppsValidation(t *testing.T) {
	svc := &FunctionsService{}
	_, err := svc.ListFunctionApps(nil, map[string]any{})
	if err == nil || err.Error() != "resource_group is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestBlobGetValidation(t *testing.T) {
	svc := &BlobService{}
	_, err := svc.GetBlob(nil, map[string]any{})
	if err == nil || err.Error() != "storage_account, container, and blob_name are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestBlobUploadValidation(t *testing.T) {
	svc := &BlobService{}
	_, err := svc.UploadBlob(nil, map[string]any{})
	if err == nil || err.Error() != "storage_account, container, and blob_name are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestBlobListValidation(t *testing.T) {
	svc := &BlobService{}
	_, err := svc.ListBlobs(nil, map[string]any{})
	if err == nil || err.Error() != "storage_account and container are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestBlobListContainersValidation(t *testing.T) {
	svc := &BlobService{}
	_, err := svc.ListContainers(nil, map[string]any{})
	if err == nil || err.Error() != "storage_account is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestBlobDeleteValidation(t *testing.T) {
	svc := &BlobService{}
	_, err := svc.DeleteBlob(nil, map[string]any{})
	if err == nil || err.Error() != "storage_account, container, and blob_name are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestServiceBusSendValidation(t *testing.T) {
	svc := &ServiceBusService{}
	_, err := svc.SendMessage(nil, map[string]any{})
	if err == nil || err.Error() != "namespace, queue_or_topic, and message_body are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestServiceBusPeekValidation(t *testing.T) {
	svc := &ServiceBusService{}
	_, err := svc.PeekMessages(nil, map[string]any{})
	if err == nil || err.Error() != "namespace and queue_or_topic are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestComputeListVMsValidation(t *testing.T) {
	svc := &ComputeService{}
	_, err := svc.ListVMs(nil, map[string]any{})
	if err == nil || err.Error() != "resource_group is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestComputeGetVMValidation(t *testing.T) {
	svc := &ComputeService{}
	_, err := svc.GetVM(nil, map[string]any{})
	if err == nil || err.Error() != "resource_group and vm_name are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestMonitorQueryMetricsValidation(t *testing.T) {
	svc := &MonitorService{}
	_, err := svc.QueryMetrics(nil, map[string]any{})
	if err == nil || err.Error() != "resource_id is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestKeyVaultGetSecretValidation(t *testing.T) {
	svc := &KeyVaultService{}
	_, err := svc.GetSecret(nil, map[string]any{})
	if err == nil || err.Error() != "vault_name and secret_name are required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestKeyVaultListSecretsValidation(t *testing.T) {
	svc := &KeyVaultService{}
	_, err := svc.ListSecrets(nil, map[string]any{})
	if err == nil || err.Error() != "vault_name is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestEntraGetUserValidation(t *testing.T) {
	svc := &EntraService{}
	_, err := svc.GetUser(nil, map[string]any{})
	if err == nil || err.Error() != "user_id is required" {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestURLBuilders(t *testing.T) {
	t.Run("ManagementURL", func(t *testing.T) {
		url := ManagementURL("sub-123", "resourceGroups/rg/providers/Microsoft.Compute/virtualMachines")
		expected := "https://management.azure.com/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines"
		if url != expected {
			t.Errorf("expected %q, got %q", expected, url)
		}
	})

	t.Run("BlobURL", func(t *testing.T) {
		url := BlobURL("myaccount", "mycontainer", "path/to/blob.txt")
		expected := "https://myaccount.blob.core.windows.net/mycontainer/path/to/blob.txt"
		if url != expected {
			t.Errorf("expected %q, got %q", expected, url)
		}
	})

	t.Run("KeyVaultURL with version", func(t *testing.T) {
		url := KeyVaultURL("myvault", "mysecret", "v1")
		expected := "https://myvault.vault.azure.net/secrets/mysecret/v1?api-version=7.4"
		if url != expected {
			t.Errorf("expected %q, got %q", expected, url)
		}
	})

	t.Run("KeyVaultURL without version", func(t *testing.T) {
		url := KeyVaultURL("myvault", "mysecret", "")
		expected := "https://myvault.vault.azure.net/secrets/mysecret?api-version=7.4"
		if url != expected {
			t.Errorf("expected %q, got %q", expected, url)
		}
	})
}

func TestBlobUploadHeaders(t *testing.T) {
	var mu sync.Mutex
	var capturedHeaders http.Header

	client := &AzureClient{
		credential: &mockCredential{},
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				mu.Lock()
				capturedHeaders = req.Header.Clone()
				mu.Unlock()
				return &http.Response{
					StatusCode: http.StatusCreated,
					Body:       http.NoBody,
					Header:     make(http.Header),
				}, nil
			}),
		},
	}
	svc := NewBlobService(client)

	result, err := svc.UploadBlob(context.Background(), map[string]any{
		"storage_account": "testaccount",
		"container":       "testcontainer",
		"blob_name":       "test.txt",
		"data":            "hello world",
		"content_type":    "text/plain",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if got := capturedHeaders.Get("x-ms-blob-type"); got != "BlockBlob" {
		t.Errorf("expected x-ms-blob-type=BlockBlob, got %q", got)
	}
	if got := capturedHeaders.Get("Content-Type"); got != "text/plain" {
		t.Errorf("expected Content-Type=text/plain, got %q", got)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	if ct, _ := resultMap["content_type"].(string); ct != "text/plain" {
		t.Errorf("expected content_type=text/plain in result, got %q", ct)
	}
}

func TestBlobGetTruncation(t *testing.T) {
	// 11MB body — exceeds maxBlobBodySize (10MB)
	largeBody := strings.Repeat("A", 11*1024*1024)

	client := &AzureClient{
		credential: &mockCredential{},
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Body:          io.NopCloser(strings.NewReader(largeBody)),
					Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
					ContentLength: int64(len(largeBody)),
				}, nil
			}),
		},
	}
	svc := NewBlobService(client)

	result, err := svc.GetBlob(context.Background(), map[string]any{
		"storage_account": "testaccount",
		"container":       "testcontainer",
		"blob_name":       "large.bin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}

	if truncated, _ := resultMap["truncated"].(bool); !truncated {
		t.Error("expected truncated=true")
	}

	b64, _ := resultMap["body_base64"].(string)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	if len(decoded) != maxBlobBodySize {
		t.Errorf("expected decoded body length %d, got %d", maxBlobBodySize, len(decoded))
	}
}

func TestBlobGetSmallBody(t *testing.T) {
	smallBody := "hello world"

	client := &AzureClient{
		credential: &mockCredential{},
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode:    http.StatusOK,
					Body:          io.NopCloser(strings.NewReader(smallBody)),
					Header:        http.Header{"Content-Type": []string{"text/plain"}},
					ContentLength: int64(len(smallBody)),
				}, nil
			}),
		},
	}
	svc := NewBlobService(client)

	result, err := svc.GetBlob(context.Background(), map[string]any{
		"storage_account": "testaccount",
		"container":       "testcontainer",
		"blob_name":       "small.txt",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}

	if _, hasTruncated := resultMap["truncated"]; hasTruncated {
		t.Error("expected no truncated key for small body")
	}

	b64, _ := resultMap["body_base64"].(string)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	if string(decoded) != smallBody {
		t.Errorf("expected %q, got %q", smallBody, string(decoded))
	}
}

func TestDoRequestDefaultContentType(t *testing.T) {
	var capturedCT string

	client := &AzureClient{
		credential: &mockCredential{},
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				capturedCT = req.Header.Get("Content-Type")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("{}")),
					Header:     make(http.Header),
				}, nil
			}),
		},
	}

	_, _, err := client.DoRequest(context.Background(), "GET", "https://example.com/test", nil, "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedCT != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", capturedCT)
	}
}

func TestDoRequestCustomContentType(t *testing.T) {
	var capturedCT string

	client := &AzureClient{
		credential: &mockCredential{},
		httpClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				capturedCT = req.Header.Get("Content-Type")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("{}")),
					Header:     make(http.Header),
				}, nil
			}),
		},
	}

	headers := map[string]string{"Content-Type": "application/xml"}
	_, _, err := client.DoRequest(context.Background(), "GET", "https://example.com/test", nil, "", headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedCT != "application/xml" {
		t.Errorf("expected Content-Type=application/xml, got %q", capturedCT)
	}
}

// roundTripFunc adapts a function to http.RoundTripper for test mocking.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

