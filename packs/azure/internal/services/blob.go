package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
)

const maxBlobBodySize = 10 * 1024 * 1024 // 10 MB

// BlobService wraps Azure Blob Storage operations.
type BlobService struct {
	client *AzureClient
}

// NewBlobService creates a Blob service.
func NewBlobService(client *AzureClient) *BlobService {
	return &BlobService{client: client}
}

// GetBlob downloads a blob with OOM protection via io.LimitReader.
// Bodies larger than maxBlobBodySize are truncated and flagged.
func (s *BlobService) GetBlob(ctx context.Context, params map[string]any) (any, error) {
	account, _ := params["storage_account"].(string)
	container, _ := params["container"].(string)
	blobName, _ := params["blob_name"].(string)
	if account == "" || container == "" || blobName == "" {
		return nil, fmt.Errorf("storage_account, container, and blob_name are required")
	}

	url := BlobURL(account, container, blobName)
	resp, err := s.client.DoRawRequest(ctx, "GET", url, nil, "https://storage.azure.com/.default", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("azure API error (status %d): %s", resp.StatusCode, string(errBody))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBlobBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read blob body: %w", err)
	}

	truncated := int64(len(body)) > maxBlobBodySize
	if truncated {
		body = body[:maxBlobBodySize]
	}

	result := map[string]any{
		"storage_account": account,
		"container":       container,
		"blob_name":       blobName,
		"status_code":     resp.StatusCode,
		"content_type":    resp.Header.Get("Content-Type"),
		"size":            resp.ContentLength,
		"body_base64":     base64.StdEncoding.EncodeToString(body),
	}
	if truncated {
		result["truncated"] = true
	}
	return result, nil
}

// UploadBlob uploads a blob.
func (s *BlobService) UploadBlob(ctx context.Context, params map[string]any) (any, error) {
	account, _ := params["storage_account"].(string)
	container, _ := params["container"].(string)
	blobName, _ := params["blob_name"].(string)
	data, _ := params["data"].(string)
	if account == "" || container == "" || blobName == "" {
		return nil, fmt.Errorf("storage_account, container, and blob_name are required")
	}

	var body []byte
	if encoding, _ := params["content_encoding"].(string); encoding == "base64" {
		var err error
		body, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("decode base64: %w", err)
		}
	} else {
		body = []byte(data)
	}

	contentType, _ := params["content_type"].(string)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	headers := map[string]string{
		"x-ms-blob-type": "BlockBlob",
		"Content-Type":   contentType,
	}

	url := BlobURL(account, container, blobName)
	_, status, err := s.client.DoRequest(ctx, "PUT", url, bytes.NewReader(body), "https://storage.azure.com/.default", headers)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"storage_account": account,
		"container":       container,
		"blob_name":       blobName,
		"status_code":     status,
		"content_type":    contentType,
		"uploaded":        true,
	}, nil
}

// ListBlobs lists blobs in a container.
func (s *BlobService) ListBlobs(ctx context.Context, params map[string]any) (any, error) {
	account, _ := params["storage_account"].(string)
	container, _ := params["container"].(string)
	if account == "" || container == "" {
		return nil, fmt.Errorf("storage_account and container are required")
	}

	url := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", account, container)
	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "https://storage.azure.com/.default", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListContainers lists containers in a storage account.
func (s *BlobService) ListContainers(ctx context.Context, params map[string]any) (any, error) {
	account, _ := params["storage_account"].(string)
	if account == "" {
		return nil, fmt.Errorf("storage_account is required")
	}

	url := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", account)
	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "https://storage.azure.com/.default", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteBlob deletes a blob.
func (s *BlobService) DeleteBlob(ctx context.Context, params map[string]any) (any, error) {
	account, _ := params["storage_account"].(string)
	container, _ := params["container"].(string)
	blobName, _ := params["blob_name"].(string)
	if account == "" || container == "" || blobName == "" {
		return nil, fmt.Errorf("storage_account, container, and blob_name are required")
	}

	url := BlobURL(account, container, blobName)
	_, _, err := s.client.DoRequest(ctx, "DELETE", url, nil, "https://storage.azure.com/.default", nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{"deleted": true, "blob_name": blobName}, nil
}

