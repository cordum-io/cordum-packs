package awsclient

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/aws/internal/config"
)

func TestResolveRegion(t *testing.T) {
	tests := []struct {
		name     string
		override string
		profile  config.Profile
		want     string
	}{
		{
			name:     "override takes priority",
			override: "eu-west-1",
			profile:  config.Profile{Region: "us-east-1"},
			want:     "eu-west-1",
		},
		{
			name:     "profile fallback",
			override: "",
			profile:  config.Profile{Region: "ap-southeast-1"},
			want:     "ap-southeast-1",
		},
		{
			name:     "default fallback",
			override: "",
			profile:  config.Profile{},
			want:     "us-east-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveRegion(tt.override, tt.profile)
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestProfileIsActionAllowed(t *testing.T) {
	tests := []struct {
		name    string
		profile config.Profile
		action  string
		want    bool
	}{
		{
			name:    "no restrictions",
			profile: config.Profile{},
			action:  "s3.get_object",
			want:    true,
		},
		{
			name:    "deny list blocks",
			profile: config.Profile{DenyActions: []string{"s3.delete_object", "ec2.*"}},
			action:  "ec2.describe_instances",
			want:    false,
		},
		{
			name:    "deny list allows other",
			profile: config.Profile{DenyActions: []string{"ec2.*"}},
			action:  "s3.get_object",
			want:    true,
		},
		{
			name:    "allow list permits match",
			profile: config.Profile{AllowActions: []string{"s3.*", "lambda.*"}},
			action:  "s3.get_object",
			want:    true,
		},
		{
			name:    "allow list blocks non-match",
			profile: config.Profile{AllowActions: []string{"s3.*"}},
			action:  "ec2.describe_instances",
			want:    false,
		},
		{
			name:    "deny takes priority over allow",
			profile: config.Profile{AllowActions: []string{"s3.*"}, DenyActions: []string{"s3.delete_object"}},
			action:  "s3.delete_object",
			want:    false,
		},
		{
			name:    "exact match",
			profile: config.Profile{AllowActions: []string{"lambda.invoke"}},
			action:  "lambda.invoke",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.profile.IsActionAllowed(tt.action)
			if got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestProfileIsResourceAllowed(t *testing.T) {
	tests := []struct {
		name    string
		profile config.Profile
		arn     string
		want    bool
	}{
		{
			name:    "empty ARN always allowed",
			profile: config.Profile{DeniedResources: []string{"arn:aws:*"}},
			arn:     "",
			want:    true,
		},
		{
			name:    "denied resource blocked",
			profile: config.Profile{DeniedResources: []string{"arn:aws:s3:::prod-*"}},
			arn:     "arn:aws:s3:::prod-bucket",
			want:    false,
		},
		{
			name:    "allowed resource permitted",
			profile: config.Profile{AllowedResources: []string{"arn:aws:s3:::dev-*"}},
			arn:     "arn:aws:s3:::dev-bucket",
			want:    true,
		},
		{
			name:    "not in allowed list blocked",
			profile: config.Profile{AllowedResources: []string{"arn:aws:s3:::dev-*"}},
			arn:     "arn:aws:s3:::prod-bucket",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.profile.IsResourceAllowed(tt.arn)
			if got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
