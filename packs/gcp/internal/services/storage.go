package services

import (
	"context"
	"fmt"
	"io"
	"strings"

	"cloud.google.com/go/storage"
	giterator "google.golang.org/api/iterator"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/gcpclient"
)

// StorageService wraps Cloud Storage operations.
type StorageService struct {
	client    *storage.Client
	projectID string
}

// NewStorageService creates a Cloud Storage service.
func NewStorageService(ctx context.Context, reqCfg gcpclient.RequestConfig) (*StorageService, error) {
	client, err := storage.NewClient(ctx, reqCfg.Options...)
	if err != nil {
		return nil, fmt.Errorf("create storage client: %w", err)
	}
	return &StorageService{
		client:    client,
		projectID: reqCfg.ProjectID,
	}, nil
}

// Close releases any client resources.
func (s *StorageService) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// GetObject fetches an object and its metadata.
func (s *StorageService) GetObject(ctx context.Context, params map[string]any) (any, error) {
	bucket := stringParam(params, "bucket")
	objectName := stringParam(params, "object_name")
	if bucket == "" || objectName == "" {
		return nil, fmt.Errorf("bucket and object_name are required")
	}

	object := s.client.Bucket(bucket).Object(objectName)
	attrs, err := object.Attrs(ctx)
	if err != nil {
		return nil, err
	}

	reader, err := object.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read object body: %w", err)
	}

	result := objectAttrsToMap(attrs)
	for key, value := range payloadResult(data) {
		result[key] = value
	}
	return result, nil
}

// UploadObject uploads an object to Cloud Storage.
func (s *StorageService) UploadObject(ctx context.Context, params map[string]any) (any, error) {
	bucket := stringParam(params, "bucket")
	objectName := stringParam(params, "object_name")
	dataValue := stringParam(params, "data")
	if bucket == "" || objectName == "" || dataValue == "" {
		return nil, fmt.Errorf("bucket, object_name, and data are required")
	}

	contentEncoding := stringParam(params, "content_encoding")
	dataEncoding := stringParam(params, "data_encoding")
	if dataEncoding == "" && strings.EqualFold(contentEncoding, "base64") {
		dataEncoding = "base64"
		contentEncoding = ""
	}

	body, err := decodeStringData(dataValue, dataEncoding)
	if err != nil {
		return nil, err
	}

	writer := s.client.Bucket(bucket).Object(objectName).NewWriter(ctx)
	writer.ContentType = stringParam(params, "content_type")
	if writer.ContentType == "" {
		writer.ContentType = "application/octet-stream"
	}
	if contentEncoding != "" {
		writer.ContentEncoding = contentEncoding
	}

	if _, err := writer.Write(body); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("write object body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close object writer: %w", err)
	}

	result := objectAttrsToMap(writer.Attrs())
	result["uploaded_bytes"] = len(body)
	return result, nil
}

// ListObjects lists objects in a bucket.
func (s *StorageService) ListObjects(ctx context.Context, params map[string]any) (any, error) {
	bucket := stringParam(params, "bucket")
	if bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}

	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}

	pageToken := stringParam(params, "page_token")
	query := &storage.Query{
		Prefix:    stringParam(params, "prefix"),
		Delimiter: stringParam(params, "delimiter"),
	}
	it := s.client.Bucket(bucket).Objects(ctx, query)
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var objects []*storage.ObjectAttrs
	nextPageToken, err := pager.NextPage(&objects)
	if err != nil {
		return nil, err
	}

	results := make([]map[string]any, 0, len(objects))
	for _, attrs := range objects {
		results = append(results, objectAttrsToMap(attrs))
	}

	return map[string]any{
		"objects":         results,
		"next_page_token": nextPageToken,
	}, nil
}

// ListBuckets lists buckets in the configured project.
func (s *StorageService) ListBuckets(ctx context.Context, params map[string]any) (any, error) {
	pageSize, err := pageSizeParam(params)
	if err != nil {
		return nil, err
	}

	pageToken := stringParam(params, "page_token")
	it := s.client.Buckets(ctx, s.projectID)
	pager := giterator.NewPager(it, int(pageSize), pageToken)

	var buckets []*storage.BucketAttrs
	nextPageToken, err := pager.NextPage(&buckets)
	if err != nil {
		return nil, err
	}

	results := make([]map[string]any, 0, len(buckets))
	for _, attrs := range buckets {
		results = append(results, bucketAttrsToMap(attrs))
	}

	return map[string]any{
		"buckets":         results,
		"next_page_token": nextPageToken,
	}, nil
}

// DeleteObject deletes an object from Cloud Storage.
func (s *StorageService) DeleteObject(ctx context.Context, params map[string]any) (any, error) {
	bucket := stringParam(params, "bucket")
	objectName := stringParam(params, "object_name")
	if bucket == "" || objectName == "" {
		return nil, fmt.Errorf("bucket and object_name are required")
	}

	if err := s.client.Bucket(bucket).Object(objectName).Delete(ctx); err != nil {
		return nil, err
	}

	return map[string]any{
		"bucket":  bucket,
		"object":  objectName,
		"deleted": true,
	}, nil
}
