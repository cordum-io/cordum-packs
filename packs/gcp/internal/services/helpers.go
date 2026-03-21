package services

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cloud.google.com/go/storage"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	defaultListPageSize = 100
	maxListPageSize     = 1000
)

var protoJSON = protojson.MarshalOptions{UseProtoNames: true}

func protoToAny(msg proto.Message) (any, error) {
	if msg == nil {
		return nil, fmt.Errorf("proto message is nil")
	}

	data, err := protoJSON.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal proto: %w", err)
	}

	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode proto json: %w", err)
	}

	return out, nil
}

func protoToMap(msg proto.Message) (map[string]any, error) {
	value, err := protoToAny(msg)
	if err != nil {
		return nil, err
	}

	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("proto message did not marshal to an object")
	}

	return result, nil
}

func protoSliceToMaps[T proto.Message](items []T) ([]map[string]any, error) {
	results := make([]map[string]any, 0, len(items))
	for _, item := range items {
		mapped, err := protoToMap(item)
		if err != nil {
			return nil, err
		}
		results = append(results, mapped)
	}
	return results, nil
}

func stringParam(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	value, ok := params[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func intParam(params map[string]any, key string, fallback int) (int, error) {
	if params == nil {
		return fallback, nil
	}
	value, ok := params[key]
	if !ok || value == nil {
		return fallback, nil
	}

	switch typed := value.(type) {
	case int:
		return typed, nil
	case int32:
		return int(typed), nil
	case int64:
		return int(typed), nil
	case float64:
		if math.Trunc(typed) != typed {
			return 0, fmt.Errorf("%s must be a whole number", key)
		}
		return int(typed), nil
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer: %w", key, err)
		}
		return int(parsed), nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return fallback, nil
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer: %w", key, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("%s must be numeric", key)
	}
}

func boolParam(params map[string]any, key string, fallback bool) (bool, error) {
	if params == nil {
		return fallback, nil
	}
	value, ok := params[key]
	if !ok || value == nil {
		return fallback, nil
	}

	switch typed := value.(type) {
	case bool:
		return typed, nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return fallback, nil
		}
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err != nil {
			return false, fmt.Errorf("%s must be boolean: %w", key, err)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("%s must be boolean", key)
	}
}

func pageSizeParam(params map[string]any) (int32, error) {
	size, err := intParam(params, "page_size", defaultListPageSize)
	if err != nil {
		return 0, err
	}
	if size <= 0 {
		size = defaultListPageSize
	}
	if size > maxListPageSize {
		size = maxListPageSize
	}
	return int32(size), nil
}

func mapStringStringParam(params map[string]any, key string) (map[string]string, error) {
	if params == nil {
		return nil, nil
	}
	value, ok := params[key]
	if !ok || value == nil {
		return nil, nil
	}

	switch typed := value.(type) {
	case map[string]string:
		out := make(map[string]string, len(typed))
		for mapKey, mapValue := range typed {
			out[mapKey] = mapValue
		}
		return out, nil
	case map[string]any:
		out := make(map[string]string, len(typed))
		for mapKey, mapValue := range typed {
			out[mapKey] = fmt.Sprint(mapValue)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be an object of string values", key)
	}
}

func stringSliceParam(params map[string]any, key string) ([]string, error) {
	if params == nil {
		return nil, nil
	}
	value, ok := params[key]
	if !ok || value == nil {
		return nil, nil
	}

	switch typed := value.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if candidate := strings.TrimSpace(item); candidate != "" {
				out = append(out, candidate)
			}
		}
		return out, nil
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			candidate := strings.TrimSpace(fmt.Sprint(item))
			if candidate != "" {
				out = append(out, candidate)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be an array of strings", key)
	}
}

func timeParam(params map[string]any, key string) (time.Time, bool, error) {
	if params == nil {
		return time.Time{}, false, nil
	}
	value, ok := params[key]
	if !ok || value == nil {
		return time.Time{}, false, nil
	}

	switch typed := value.(type) {
	case time.Time:
		return typed, true, nil
	case string:
		candidate := strings.TrimSpace(typed)
		if candidate == "" {
			return time.Time{}, false, nil
		}
		parsed, err := time.Parse(time.RFC3339, candidate)
		if err == nil {
			return parsed, true, nil
		}
		parsed, err = time.Parse(time.RFC3339Nano, candidate)
		if err == nil {
			return parsed, true, nil
		}
		return time.Time{}, false, fmt.Errorf("%s must be RFC3339", key)
	case float64:
		return time.Unix(int64(typed), 0).UTC(), true, nil
	case int64:
		return time.Unix(typed, 0).UTC(), true, nil
	case int:
		return time.Unix(int64(typed), 0).UTC(), true, nil
	default:
		return time.Time{}, false, fmt.Errorf("%s must be RFC3339 or unix seconds", key)
	}
}

func decodeStringData(value, encoding string) ([]byte, error) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "", "text", "plain", "utf8", "utf-8":
		return []byte(value), nil
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode base64 payload: %w", err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unsupported data encoding %q", encoding)
	}
}

func payloadResult(data []byte) map[string]any {
	result := map[string]any{
		"data_base64": base64.StdEncoding.EncodeToString(data),
	}
	if utf8.Valid(data) {
		result["data"] = string(data)
	}
	return result
}

func isFullResource(value string) bool {
	candidate := strings.TrimSpace(value)
	return strings.HasPrefix(candidate, "projects/") ||
		strings.HasPrefix(candidate, "organizations/") ||
		strings.HasPrefix(candidate, "folders/") ||
		strings.HasPrefix(candidate, "roles/")
}

func ptr[T any](value T) *T {
	return &value
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func objectAttrsToMap(attrs *storage.ObjectAttrs) map[string]any {
	if attrs == nil {
		return map[string]any{}
	}

	result := map[string]any{
		"bucket":              attrs.Bucket,
		"name":                attrs.Name,
		"size":                attrs.Size,
		"content_type":        attrs.ContentType,
		"content_encoding":    attrs.ContentEncoding,
		"cache_control":       attrs.CacheControl,
		"storage_class":       attrs.StorageClass,
		"etag":                attrs.Etag,
		"generation":          attrs.Generation,
		"metageneration":      attrs.Metageneration,
		"crc32c":              attrs.CRC32C,
		"media_link":          attrs.MediaLink,
		"time_created":        formatTime(attrs.Created),
		"updated":             formatTime(attrs.Updated),
		"deleted":             formatTime(attrs.Deleted),
		"customer_key_sha256": attrs.CustomerKeySHA256,
	}
	if len(attrs.MD5) > 0 {
		result["md5_hash_base64"] = base64.StdEncoding.EncodeToString(attrs.MD5)
	}
	if len(attrs.Metadata) > 0 {
		result["metadata"] = attrs.Metadata
	}
	return result
}

func bucketAttrsToMap(attrs *storage.BucketAttrs) map[string]any {
	if attrs == nil {
		return map[string]any{}
	}

	result := map[string]any{
		"name":                     attrs.Name,
		"location":                 attrs.Location,
		"location_type":            attrs.LocationType,
		"storage_class":            attrs.StorageClass,
		"rpo":                      fmt.Sprint(attrs.RPO),
		"default_event_based_hold": attrs.DefaultEventBasedHold,
		"versioning_enabled":       attrs.VersioningEnabled,
		"time_created":             formatTime(attrs.Created),
		"updated":                  formatTime(attrs.Updated),
	}
	if len(attrs.Labels) > 0 {
		result["labels"] = attrs.Labels
	}
	return result
}
