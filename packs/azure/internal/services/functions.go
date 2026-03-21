package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// FunctionsService wraps Azure Functions operations.
type FunctionsService struct {
	client         *AzureClient
	subscriptionID string
	resourceGroup  string
}

// NewFunctionsService creates a Functions service.
func NewFunctionsService(client *AzureClient, subscriptionID, resourceGroup string) *FunctionsService {
	return &FunctionsService{client: client, subscriptionID: subscriptionID, resourceGroup: resourceGroup}
}

// InvokeFunction invokes an Azure Function via its HTTP trigger.
func (s *FunctionsService) InvokeFunction(ctx context.Context, params map[string]any) (any, error) {
	appName, _ := params["function_app"].(string)
	funcName, _ := params["function_name"].(string)
	if appName == "" || funcName == "" {
		return nil, fmt.Errorf("function_app and function_name are required")
	}

	// Build function URL (assumes HTTP trigger)
	url := fmt.Sprintf("https://%s.azurewebsites.net/api/%s", appName, funcName)

	var body *bytes.Reader
	if payload := params["payload"]; payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		body = bytes.NewReader(data)
	} else {
		body = bytes.NewReader(nil)
	}

	method := "POST"
	if m, ok := params["method"].(string); ok && m != "" {
		method = m
	}

	result, status, err := s.client.DoRequest(ctx, method, url, body, "", nil)
	if err != nil {
		return nil, err
	}

	return map[string]any{"status_code": status, "result": result}, nil
}

// ListFunctionApps lists function apps in the resource group.
func (s *FunctionsService) ListFunctionApps(ctx context.Context, params map[string]any) (any, error) {
	rg := s.resourceGroup
	if r, ok := params["resource_group"].(string); ok && r != "" {
		rg = r
	}
	if rg == "" {
		return nil, fmt.Errorf("resource_group is required")
	}

	url := ManagementURL(s.subscriptionID,
		fmt.Sprintf("resourceGroups/%s/providers/Microsoft.Web/sites?api-version=2023-12-01&$filter=kind eq 'functionapp'", rg))

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "", nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}
