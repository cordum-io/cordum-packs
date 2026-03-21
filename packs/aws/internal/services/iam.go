package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IAMService wraps AWS IAM read-only operations.
type IAMService struct {
	client *iam.Client
}

// NewIAMService creates an IAM service from an AWS config.
func NewIAMService(cfg aws.Config) *IAMService {
	return &IAMService{client: iam.NewFromConfig(cfg)}
}

// GetUser returns details about an IAM user.
func (s *IAMService) GetUser(ctx context.Context, params map[string]any) (any, error) {
	input := &iam.GetUserInput{}
	if userName, ok := params["user_name"].(string); ok && userName != "" {
		input.UserName = aws.String(userName)
	}

	out, err := s.client.GetUser(ctx, input)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"user_name":   aws.ToString(out.User.UserName),
		"user_id":     aws.ToString(out.User.UserId),
		"arn":         aws.ToString(out.User.Arn),
		"create_date": out.User.CreateDate.String(),
	}, nil
}

// ListUsers lists IAM users.
func (s *IAMService) ListUsers(ctx context.Context, params map[string]any) (any, error) {
	input := &iam.ListUsersInput{}
	if maxItems, ok := params["max_items"].(float64); ok && maxItems > 0 {
		input.MaxItems = aws.Int32(int32(maxItems))
	}

	out, err := s.client.ListUsers(ctx, input)
	if err != nil {
		return nil, err
	}

	users := make([]map[string]any, 0, len(out.Users))
	for _, u := range out.Users {
		users = append(users, map[string]any{
			"user_name": aws.ToString(u.UserName),
			"user_id":   aws.ToString(u.UserId),
			"arn":       aws.ToString(u.Arn),
		})
	}
	return map[string]any{"users": users, "count": len(users)}, nil
}

// ListRoles lists IAM roles.
func (s *IAMService) ListRoles(ctx context.Context, params map[string]any) (any, error) {
	input := &iam.ListRolesInput{}
	if maxItems, ok := params["max_items"].(float64); ok && maxItems > 0 {
		input.MaxItems = aws.Int32(int32(maxItems))
	}

	out, err := s.client.ListRoles(ctx, input)
	if err != nil {
		return nil, err
	}

	roles := make([]map[string]any, 0, len(out.Roles))
	for _, r := range out.Roles {
		roles = append(roles, map[string]any{
			"role_name": aws.ToString(r.RoleName),
			"role_id":   aws.ToString(r.RoleId),
			"arn":       aws.ToString(r.Arn),
		})
	}
	return map[string]any{"roles": roles, "count": len(roles)}, nil
}

// ListPolicies lists IAM policies.
func (s *IAMService) ListPolicies(ctx context.Context, params map[string]any) (any, error) {
	input := &iam.ListPoliciesInput{Scope: "Local"}
	if scope, ok := params["scope"].(string); ok && scope != "" {
		input.Scope = iamtypes.PolicyScopeType(scope)
	}
	if maxItems, ok := params["max_items"].(float64); ok && maxItems > 0 {
		input.MaxItems = aws.Int32(int32(maxItems))
	}

	out, err := s.client.ListPolicies(ctx, input)
	if err != nil {
		return nil, err
	}

	policies := make([]map[string]any, 0, len(out.Policies))
	for _, p := range out.Policies {
		policies = append(policies, map[string]any{
			"policy_name": aws.ToString(p.PolicyName),
			"policy_id":   aws.ToString(p.PolicyId),
			"arn":         aws.ToString(p.Arn),
		})
	}
	return map[string]any{"policies": policies, "count": len(policies)}, nil
}
