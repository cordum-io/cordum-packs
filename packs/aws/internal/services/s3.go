package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const maxS3BodySize = 10 * 1024 * 1024 // 10 MB limit for inline responses

// S3Service wraps AWS S3 operations.
type S3Service struct {
	client *s3.Client
}

// NewS3Service creates an S3 service from an AWS config.
func NewS3Service(cfg aws.Config) *S3Service {
	return &S3Service{client: s3.NewFromConfig(cfg)}
}

// GetObject downloads an S3 object.
func (s *S3Service) GetObject(ctx context.Context, params map[string]any) (any, error) {
	bucket, _ := params["bucket"].(string)
	key, _ := params["key"].(string)
	if bucket == "" || key == "" {
		return nil, fmt.Errorf("bucket and key are required")
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID, ok := params["version_id"].(string); ok && versionID != "" {
		input.VersionId = aws.String(versionID)
	}

	out, err := s.client.GetObject(ctx, input)
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()

	body, err := io.ReadAll(io.LimitReader(out.Body, maxS3BodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read object body: %w", err)
	}

	result := map[string]any{
		"bucket":       bucket,
		"key":          key,
		"content_type": aws.ToString(out.ContentType),
		"size":         aws.ToInt64(out.ContentLength),
	}

	if len(body) > maxS3BodySize {
		result["truncated"] = true
		result["body_base64"] = base64.StdEncoding.EncodeToString(body[:maxS3BodySize])
	} else {
		result["body_base64"] = base64.StdEncoding.EncodeToString(body)
	}

	return result, nil
}

// PutObject uploads an object to S3.
func (s *S3Service) PutObject(ctx context.Context, params map[string]any) (any, error) {
	bucket, _ := params["bucket"].(string)
	key, _ := params["key"].(string)
	bodyStr, _ := params["body"].(string)
	if bucket == "" || key == "" {
		return nil, fmt.Errorf("bucket and key are required")
	}

	var body []byte
	contentEncoding, _ := params["content_encoding"].(string)
	if contentEncoding == "base64" {
		var err error
		body, err = base64.StdEncoding.DecodeString(bodyStr)
		if err != nil {
			return nil, fmt.Errorf("decode base64 body: %w", err)
		}
	} else {
		body = []byte(bodyStr)
	}

	contentType, _ := params["content_type"].(string)
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
	}

	out, err := s.client.PutObject(ctx, input)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"bucket": bucket,
		"key":    key,
		"etag":   aws.ToString(out.ETag),
	}, nil
}

// ListBuckets lists S3 buckets.
func (s *S3Service) ListBuckets(ctx context.Context, _ map[string]any) (any, error) {
	out, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	buckets := make([]map[string]any, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		buckets = append(buckets, map[string]any{
			"name":          aws.ToString(b.Name),
			"creation_date": b.CreationDate.String(),
		})
	}
	return map[string]any{"buckets": buckets}, nil
}

// ListObjects lists objects in a bucket.
func (s *S3Service) ListObjects(ctx context.Context, params map[string]any) (any, error) {
	bucket, _ := params["bucket"].(string)
	if bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}

	input := &s3.ListObjectsV2Input{Bucket: aws.String(bucket)}
	if prefix, ok := params["prefix"].(string); ok && prefix != "" {
		input.Prefix = aws.String(prefix)
	}
	if maxKeys, ok := params["max_keys"].(float64); ok && maxKeys > 0 {
		input.MaxKeys = aws.Int32(int32(maxKeys))
	}

	out, err := s.client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, err
	}

	objects := make([]map[string]any, 0, len(out.Contents))
	for _, obj := range out.Contents {
		objects = append(objects, map[string]any{
			"key":           aws.ToString(obj.Key),
			"size":          aws.ToInt64(obj.Size),
			"last_modified": obj.LastModified.String(),
		})
	}
	return map[string]any{"objects": objects, "count": len(objects)}, nil
}

// HeadObject returns object metadata.
func (s *S3Service) HeadObject(ctx context.Context, params map[string]any) (any, error) {
	bucket, _ := params["bucket"].(string)
	key, _ := params["key"].(string)
	if bucket == "" || key == "" {
		return nil, fmt.Errorf("bucket and key are required")
	}

	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"content_type":   aws.ToString(out.ContentType),
		"content_length": aws.ToInt64(out.ContentLength),
		"etag":           aws.ToString(out.ETag),
		"last_modified":  out.LastModified.String(),
	}, nil
}

// DeleteObject deletes an object from S3.
func (s *S3Service) DeleteObject(ctx context.Context, params map[string]any) (any, error) {
	bucket, _ := params["bucket"].(string)
	key, _ := params["key"].(string)
	if bucket == "" || key == "" {
		return nil, fmt.Errorf("bucket and key are required")
	}

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}

	return map[string]any{"deleted": true, "bucket": bucket, "key": key}, nil
}
