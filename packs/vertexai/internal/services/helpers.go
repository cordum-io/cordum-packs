package services

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	cloudpb "cloud.google.com/go/aiplatform/apiv1/aiplatformpb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
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

func anyToProto(value any, dst proto.Message) error {
	if value == nil || dst == nil {
		return nil
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal proto input: %w", err)
	}
	if err := protojson.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode proto input: %w", err)
	}
	return nil
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
		if float64(int(typed)) != typed {
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

func floatParam(params map[string]any, key string) (float64, bool, error) {
	if params == nil {
		return 0, false, nil
	}
	value, ok := params[key]
	if !ok || value == nil {
		return 0, false, nil
	}

	switch typed := value.(type) {
	case float64:
		return typed, true, nil
	case float32:
		return float64(typed), true, nil
	case int:
		return float64(typed), true, nil
	case int32:
		return float64(typed), true, nil
	case int64:
		return float64(typed), true, nil
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false, fmt.Errorf("%s must be numeric: %w", key, err)
		}
		return parsed, true, nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, false, nil
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return 0, false, fmt.Errorf("%s must be numeric: %w", key, err)
		}
		return parsed, true, nil
	default:
		return 0, false, fmt.Errorf("%s must be numeric", key)
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
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "":
			return fallback, nil
		default:
			return false, fmt.Errorf("%s must be boolean", key)
		}
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
	}
	return nil, fmt.Errorf("%s must be an object of string values", key)
}

func mapStringStringOrNil(params map[string]any, key string) map[string]string {
	value, err := mapStringStringParam(params, key)
	if err != nil {
		return nil
	}
	return value
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
	}
	return nil, fmt.Errorf("%s must be an array of strings", key)
}

func readMaskParam(params map[string]any, key string) (*fieldmaskpb.FieldMask, error) {
	if params == nil {
		return nil, nil
	}
	value, ok := params[key]
	if !ok || value == nil {
		return nil, nil
	}

	var paths []string
	switch typed := value.(type) {
	case string:
		for _, part := range strings.Split(typed, ",") {
			if candidate := strings.TrimSpace(part); candidate != "" {
				paths = append(paths, candidate)
			}
		}
	case []string:
		for _, part := range typed {
			if candidate := strings.TrimSpace(part); candidate != "" {
				paths = append(paths, candidate)
			}
		}
	case []any:
		for _, part := range typed {
			if candidate := strings.TrimSpace(fmt.Sprint(part)); candidate != "" {
				paths = append(paths, candidate)
			}
		}
	default:
		return nil, fmt.Errorf("%s must be a comma-separated string or string array", key)
	}

	if len(paths) == 0 {
		return nil, nil
	}
	return &fieldmaskpb.FieldMask{Paths: paths}, nil
}

func structValueFromAny(value any) (*structpb.Value, error) {
	if value == nil {
		return nil, nil
	}
	return structpb.NewValue(value)
}

func marshalString(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return "", fmt.Errorf("marshal content: %w", err)
		}
		return string(data), nil
	}
}

func contentFromAny(role string, value any) (*cloudpb.Content, error) {
	text, err := marshalString(value)
	if err != nil {
		return nil, err
	}
	return &cloudpb.Content{
		Role: normalizeContentRole(role),
		Parts: []*cloudpb.Part{
			{Data: &cloudpb.Part_Text{Text: text}},
		},
	}, nil
}

func contentsFromPromptOrMessages(params map[string]any) ([]*cloudpb.Content, error) {
	if prompt := stringParam(params, "prompt"); prompt != "" {
		content, err := contentFromAny("user", prompt)
		if err != nil {
			return nil, err
		}
		return []*cloudpb.Content{content}, nil
	}

	rawMessages, ok := params["messages"]
	if !ok || rawMessages == nil {
		return nil, fmt.Errorf("prompt or messages is required")
	}
	messages, ok := rawMessages.([]any)
	if !ok {
		return nil, fmt.Errorf("messages must be an array")
	}
	if len(messages) == 0 {
		return nil, fmt.Errorf("messages must not be empty")
	}

	contents := make([]*cloudpb.Content, 0, len(messages))
	for _, item := range messages {
		message, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("messages entries must be objects")
		}
		content, err := contentFromAny(stringParam(message, "role"), message["content"])
		if err != nil {
			return nil, err
		}
		contents = append(contents, content)
	}
	return contents, nil
}

func systemInstructionFromAny(value any) (*cloudpb.Content, error) {
	if value == nil {
		return nil, nil
	}
	if text := strings.TrimSpace(fmt.Sprint(value)); text == "" {
		return nil, nil
	}
	return contentFromAny("", value)
}

func generationConfigFromParams(value any, maxTokensPerRequest int) (*cloudpb.GenerationConfig, error) {
	rawConfig, ok := value.(map[string]any)
	if !ok || rawConfig == nil {
		return nil, nil
	}

	cfg := &cloudpb.GenerationConfig{}
	if temperature, ok, err := floatParam(rawConfig, "temperature"); err != nil {
		return nil, err
	} else if ok {
		temp := float32(temperature)
		cfg.Temperature = &temp
	}
	if topP, ok, err := floatParam(rawConfig, "top_p"); err != nil {
		return nil, err
	} else if ok {
		value := float32(topP)
		cfg.TopP = &value
	}
	if topK, ok, err := floatParam(rawConfig, "top_k"); err != nil {
		return nil, err
	} else if ok {
		value := float32(topK)
		cfg.TopK = &value
	}
	if maxTokens, err := intParam(rawConfig, "max_tokens", 0); err != nil {
		return nil, err
	} else if maxTokens > 0 {
		if maxTokensPerRequest > 0 && maxTokens > maxTokensPerRequest {
			return nil, fmt.Errorf("generation_config.max_tokens exceeds configured limit of %d", maxTokensPerRequest)
		}
		value := int32(maxTokens)
		cfg.MaxOutputTokens = &value
	}
	if stopSequences, err := stringSliceParam(rawConfig, "stop_sequences"); err != nil {
		return nil, err
	} else if len(stopSequences) > 0 {
		cfg.StopSequences = stopSequences
	}
	return cfg, nil
}

func safetySettingsFromParams(value any) ([]*cloudpb.SafetySetting, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("safety_settings must be an array")
	}

	settings := make([]*cloudpb.SafetySetting, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("safety_settings entries must be objects")
		}
		categoryName := strings.ToUpper(stringParam(entry, "category"))
		thresholdName := strings.ToUpper(stringParam(entry, "threshold"))
		if categoryName == "" || thresholdName == "" {
			return nil, fmt.Errorf("safety_settings entries require category and threshold")
		}
		categoryValue, ok := cloudpb.HarmCategory_value[categoryName]
		if !ok {
			return nil, fmt.Errorf("unsupported safety category %q", categoryName)
		}
		thresholdValue, ok := cloudpb.SafetySetting_HarmBlockThreshold_value[thresholdName]
		if !ok {
			return nil, fmt.Errorf("unsupported safety threshold %q", thresholdName)
		}

		setting := &cloudpb.SafetySetting{
			Category:  cloudpb.HarmCategory(categoryValue),
			Threshold: cloudpb.SafetySetting_HarmBlockThreshold(thresholdValue),
		}
		if methodName := strings.ToUpper(stringParam(entry, "method")); methodName != "" {
			methodValue, ok := cloudpb.SafetySetting_HarmBlockMethod_value[methodName]
			if !ok {
				return nil, fmt.Errorf("unsupported safety method %q", methodName)
			}
			setting.Method = cloudpb.SafetySetting_HarmBlockMethod(methodValue)
		}
		settings = append(settings, setting)
	}
	return settings, nil
}

func embeddingTaskType(value string) (cloudpb.EmbedContentRequest_EmbeddingTaskType, error) {
	name := strings.ToUpper(strings.TrimSpace(value))
	if name == "" {
		return cloudpb.EmbedContentRequest_UNSPECIFIED, nil
	}
	enumValue, ok := cloudpb.EmbedContentRequest_EmbeddingTaskType_value[name]
	if !ok {
		return 0, fmt.Errorf("unsupported task_type %q", value)
	}
	return cloudpb.EmbedContentRequest_EmbeddingTaskType(enumValue), nil
}

func normalizeContentRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "assistant":
		return "model"
	case "system":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(role))
	}
}

func locationParent(projectID, location string) string {
	return fmt.Sprintf("projects/%s/locations/%s", projectID, location)
}

func modelResource(projectID, location, model string) string {
	trimmed := strings.TrimSpace(model)
	if strings.HasPrefix(trimmed, "projects/") || strings.HasPrefix(trimmed, "publishers/") {
		return trimmed
	}
	return fmt.Sprintf("%s/publishers/google/models/%s", locationParent(projectID, location), trimmed)
}

func endpointResource(projectID, location, endpointID string) string {
	trimmed := strings.TrimSpace(endpointID)
	if strings.HasPrefix(trimmed, "projects/") {
		return trimmed
	}
	return fmt.Sprintf("%s/endpoints/%s", locationParent(projectID, location), trimmed)
}

func batchJobResource(projectID, location, jobID string) string {
	trimmed := strings.TrimSpace(jobID)
	if strings.HasPrefix(trimmed, "projects/") {
		return trimmed
	}
	return fmt.Sprintf("%s/batchPredictionJobs/%s", locationParent(projectID, location), trimmed)
}

func trainingPipelineResource(projectID, location, pipelineID string) string {
	trimmed := strings.TrimSpace(pipelineID)
	if strings.HasPrefix(trimmed, "projects/") {
		return trimmed
	}
	return fmt.Sprintf("%s/trainingPipelines/%s", locationParent(projectID, location), trimmed)
}

func httpBodyResult(contentType string, data []byte) map[string]any {
	result := map[string]any{
		"content_type": contentType,
		"data_base64":  base64.StdEncoding.EncodeToString(data),
	}
	if utf8.Valid(data) {
		result["data"] = string(data)
	}
	return result
}

func defaultDisplayName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().Unix())
}

func tokenUsageResult(promptTokens, completionTokens, totalTokens int) map[string]any {
	return map[string]any{
		"prompt_tokens":     promptTokens,
		"completion_tokens": completionTokens,
		"total_tokens":      totalTokens,
	}
}

func usageMetadataToTokenUsage(usage *cloudpb.UsageMetadata) map[string]any {
	if usage == nil {
		return tokenUsageResult(0, 0, 0)
	}
	return tokenUsageResult(
		int(usage.GetPromptTokenCount()),
		int(usage.GetCandidatesTokenCount()),
		int(usage.GetTotalTokenCount()),
	)
}

func generateUsageMetadataToTokenUsage(usage *cloudpb.GenerateContentResponse_UsageMetadata) map[string]any {
	if usage == nil {
		return tokenUsageResult(0, 0, 0)
	}
	return tokenUsageResult(
		int(usage.GetPromptTokenCount()),
		int(usage.GetCandidatesTokenCount()),
		int(usage.GetTotalTokenCount()),
	)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func ptr[T any](value T) *T {
	return &value
}

func ptrOptional(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return ptr(value)
}
