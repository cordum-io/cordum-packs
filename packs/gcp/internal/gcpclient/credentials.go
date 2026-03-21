package gcpclient

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/config"
)

var defaultScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// DefaultScopes returns the scopes used for ADC and impersonation.
func DefaultScopes() []string {
	return append([]string(nil), defaultScopes...)
}

// BuildClientOptions resolves credentials and user-agent options for Google clients.
func BuildClientOptions(ctx context.Context, profile config.Profile, userAgent string) ([]option.ClientOption, error) {
	var baseOpts []option.ClientOption

	credentialFile := profile.ResolveCredentialsFile()
	if credentialFile != "" {
		if _, err := os.Stat(credentialFile); err != nil {
			return nil, fmt.Errorf("credentials file %q: %w", credentialFile, err)
		}
		baseOpts = append(baseOpts, option.WithCredentialsFile(credentialFile))
	}

	if strings.TrimSpace(profile.ImpersonateServiceAccount) != "" {
		tokenSource, err := impersonate.CredentialsTokenSource(
			ctx,
			impersonate.CredentialsConfig{
				TargetPrincipal: profile.ImpersonateServiceAccount,
				Scopes:          DefaultScopes(),
			},
			baseOpts...,
		)
		if err != nil {
			return nil, fmt.Errorf("impersonate credentials: %w", err)
		}
		baseOpts = []option.ClientOption{option.WithTokenSource(tokenSource)}
	}

	if strings.TrimSpace(userAgent) != "" {
		baseOpts = append(baseOpts, option.WithUserAgent(strings.TrimSpace(userAgent)))
	}

	return baseOpts, nil
}
