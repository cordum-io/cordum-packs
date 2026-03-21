package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// LambdaService wraps AWS Lambda operations.
type LambdaService struct {
	client *lambda.Client
}

// NewLambdaService creates a Lambda service from an AWS config.
func NewLambdaService(cfg aws.Config) *LambdaService {
	return &LambdaService{client: lambda.NewFromConfig(cfg)}
}

// Invoke invokes a Lambda function.
func (s *LambdaService) Invoke(ctx context.Context, params map[string]any) (any, error) {
	functionName, _ := params["function_name"].(string)
	if functionName == "" {
		return nil, fmt.Errorf("function_name is required")
	}

	input := &lambda.InvokeInput{
		FunctionName: aws.String(functionName),
	}

	if invocationType, ok := params["invocation_type"].(string); ok && invocationType != "" {
		input.InvocationType = types.InvocationType(invocationType)
	}
	if qualifier, ok := params["qualifier"].(string); ok && qualifier != "" {
		input.Qualifier = aws.String(qualifier)
	}

	// Marshal payload
	if payload := params["payload"]; payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		input.Payload = data
	}

	out, err := s.client.Invoke(ctx, input)
	if err != nil {
		return nil, err
	}

	result := map[string]any{
		"status_code":      out.StatusCode,
		"executed_version": aws.ToString(out.ExecutedVersion),
	}
	if out.FunctionError != nil {
		result["function_error"] = *out.FunctionError
	}
	if len(out.Payload) > 0 {
		var payload any
		if json.Unmarshal(out.Payload, &payload) == nil {
			result["payload"] = payload
		} else {
			result["payload"] = string(out.Payload)
		}
	}
	return result, nil
}

// GetFunction returns Lambda function configuration.
func (s *LambdaService) GetFunction(ctx context.Context, params map[string]any) (any, error) {
	functionName, _ := params["function_name"].(string)
	if functionName == "" {
		return nil, fmt.Errorf("function_name is required")
	}

	out, err := s.client.GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: aws.String(functionName),
	})
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"function_name": aws.ToString(out.Configuration.FunctionName),
		"function_arn":  aws.ToString(out.Configuration.FunctionArn),
		"runtime":       string(out.Configuration.Runtime),
		"handler":       aws.ToString(out.Configuration.Handler),
		"memory_size":   aws.ToInt32(out.Configuration.MemorySize),
		"timeout":       aws.ToInt32(out.Configuration.Timeout),
		"last_modified": aws.ToString(out.Configuration.LastModified),
		"state":         string(out.Configuration.State),
	}, nil
}

// ListFunctions lists Lambda functions.
func (s *LambdaService) ListFunctions(ctx context.Context, params map[string]any) (any, error) {
	input := &lambda.ListFunctionsInput{}
	if maxItems, ok := params["max_items"].(float64); ok && maxItems > 0 {
		input.MaxItems = aws.Int32(int32(maxItems))
	}

	out, err := s.client.ListFunctions(ctx, input)
	if err != nil {
		return nil, err
	}

	functions := make([]map[string]any, 0, len(out.Functions))
	for _, fn := range out.Functions {
		functions = append(functions, map[string]any{
			"function_name": aws.ToString(fn.FunctionName),
			"function_arn":  aws.ToString(fn.FunctionArn),
			"runtime":       string(fn.Runtime),
			"last_modified": aws.ToString(fn.LastModified),
		})
	}
	return map[string]any{"functions": functions}, nil
}
