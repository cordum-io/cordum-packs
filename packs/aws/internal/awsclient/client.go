package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/cordum-io/cordum-packs/packs/aws/internal/config"
)

// NewAWSConfig builds an aws.Config for the given profile and optional region override.
// Credential resolution order:
//  1. Explicit static credentials from profile (access_key_id + secret_access_key)
//  2. Default credential chain (env vars, shared credentials, EC2 metadata, etc.)
//  3. STS AssumeRole if role_arn is set
func NewAWSConfig(ctx context.Context, profile config.Profile, regionOverride string) (aws.Config, error) {
	region := regionOverride
	if region == "" {
		region = profile.Region
	}
	if region == "" {
		region = "us-east-1"
	}

	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(region))

	// Static credentials from profile
	accessKey := profile.ResolveAccessKeyID()
	secretKey := profile.ResolveSecretAccessKey()
	if accessKey != "" && secretKey != "" {
		sessionToken := profile.ResolveSessionToken()
		staticCreds := credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken)
		opts = append(opts, awsconfig.WithCredentialsProvider(staticCreds))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load aws config: %w", err)
	}

	// STS AssumeRole for cross-account access
	if profile.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		assumeOpts := func(o *stscreds.AssumeRoleOptions) {
			if profile.ExternalID != "" {
				o.ExternalID = aws.String(profile.ExternalID)
			}
		}
		roleProvider := stscreds.NewAssumeRoleProvider(stsClient, profile.RoleARN, assumeOpts)
		cfg.Credentials = aws.NewCredentialsCache(roleProvider)
	}

	return cfg, nil
}
