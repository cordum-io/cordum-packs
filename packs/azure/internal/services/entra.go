package services

import (
	"context"
	"fmt"
)

// EntraService wraps Microsoft Entra ID (Azure AD) read operations.
type EntraService struct {
	client *AzureClient
}

// NewEntraService creates an Entra ID service.
func NewEntraService(client *AzureClient) *EntraService {
	return &EntraService{client: client}
}

// GetUser gets a user by ID or UPN.
func (s *EntraService) GetUser(ctx context.Context, params map[string]any) (any, error) {
	userID, _ := params["user_id"].(string)
	if userID == "" {
		return nil, fmt.Errorf("user_id is required")
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", userID)
	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "https://graph.microsoft.com/.default", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListUsers lists users.
func (s *EntraService) ListUsers(ctx context.Context, params map[string]any) (any, error) {
	url := "https://graph.microsoft.com/v1.0/users?$top=100"
	if filter, ok := params["filter"].(string); ok && filter != "" {
		url += "&$filter=" + filter
	}

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "https://graph.microsoft.com/.default", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListGroups lists groups.
func (s *EntraService) ListGroups(ctx context.Context, params map[string]any) (any, error) {
	url := "https://graph.microsoft.com/v1.0/groups?$top=100"
	if filter, ok := params["filter"].(string); ok && filter != "" {
		url += "&$filter=" + filter
	}

	result, _, err := s.client.DoRequest(ctx, "GET", url, nil, "https://graph.microsoft.com/.default", nil)
	if err != nil {
		return nil, err
	}
	return result, nil
}
