package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/cordum-io/cordum-packs/packs/aws/internal/config"
)

// ValidateCredentials checks that the AWS config has resolvable credentials.
func ValidateCredentials(ctx context.Context, cfg aws.Config) error {
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("resolve aws credentials: %w", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return fmt.Errorf("aws credentials are empty — check env vars or profile config")
	}
	return nil
}

// ResolveRegion returns the effective region (override > profile > default).
func ResolveRegion(regionOverride string, profile config.Profile) string {
	if regionOverride != "" {
		return regionOverride
	}
	if profile.Region != "" {
		return profile.Region
	}
	return "us-east-1"
}
