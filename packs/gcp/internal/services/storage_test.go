package services

import (
	"context"
	"testing"
)

func TestStorageGetValidation(t *testing.T) {
	t.Parallel()

	svc := &StorageService{}
	_, err := svc.GetObject(context.Background(), map[string]any{})
	assertErrMsg(t, err, "bucket and object_name are required")
}

func TestStorageUploadValidation(t *testing.T) {
	t.Parallel()

	svc := &StorageService{}
	_, err := svc.UploadObject(context.Background(), map[string]any{})
	assertErrMsg(t, err, "bucket, object_name, and data are required")
}

func TestStorageUploadRejectsUnsupportedEncoding(t *testing.T) {
	t.Parallel()

	svc := &StorageService{}
	_, err := svc.UploadObject(context.Background(), map[string]any{
		"bucket":        "demo-bucket",
		"object_name":   "demo.txt",
		"data":          "payload",
		"data_encoding": "gzip",
	})
	assertErrMsg(t, err, `unsupported data encoding "gzip"`)
}

func TestStorageListValidation(t *testing.T) {
	t.Parallel()

	svc := &StorageService{}
	_, err := svc.ListObjects(context.Background(), map[string]any{})
	assertErrMsg(t, err, "bucket is required")
}

func TestStorageDeleteValidation(t *testing.T) {
	t.Parallel()

	svc := &StorageService{}
	_, err := svc.DeleteObject(context.Background(), map[string]any{})
	assertErrMsg(t, err, "bucket and object_name are required")
}
