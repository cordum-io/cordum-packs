package vertexclient

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	"github.com/cordum-io/cordum-packs/packs/vertexai/internal/config"
)

var defaultScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

// RequestConfig captures the resolved project/location/profile settings for a Vertex AI request.
type RequestConfig struct {
	Profile             config.Profile
	ProjectID           string
	Location            string
	MaxTokensPerRequest int
	Options             []option.ClientOption
}

// DefaultScopes returns the scopes used for ADC and impersonation.
func DefaultScopes() []string {
	return append([]string(nil), defaultScopes...)
}

// ResolveRequestConfig resolves profile, project/location, token limits, and client options.
func ResolveRequestConfig(ctx context.Context, cfg config.Config, profileName, projectOverride, locationOverride string) (RequestConfig, error) {
	profile := cfg.ResolveProfile(profileName)
	projectID := profile.ResolveProjectID(strings.TrimSpace(projectOverride), cfg.DefaultProjectID)
	if projectID == "" {
		return RequestConfig{}, fmt.Errorf("project_id is required")
	}

	location := profile.ResolveLocation(strings.TrimSpace(locationOverride), cfg.DefaultLocation)
	clientOptions, err := BuildClientOptions(ctx, profile, cfg.UserAgent, location)
	if err != nil {
		return RequestConfig{}, err
	}

	return RequestConfig{
		Profile:             profile,
		ProjectID:           projectID,
		Location:            location,
		MaxTokensPerRequest: profile.ResolveMaxTokens(cfg.MaxTokensPerRequest),
		Options:             clientOptions,
	}, nil
}

// BuildClientOptions resolves credentials, impersonation, user-agent, and regional endpoint options.
func BuildClientOptions(ctx context.Context, profile config.Profile, userAgent, location string) ([]option.ClientOption, error) {
	var baseOpts []option.ClientOption

	credentialsFile := profile.ResolveCredentialsFile()
	if credentialsFile != "" {
		if _, err := os.Stat(credentialsFile); err != nil {
			return nil, fmt.Errorf("credentials file %q: %w", credentialsFile, err)
		}
		baseOpts = append(baseOpts, option.WithCredentialsFile(credentialsFile))
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

	if trimmedLocation := strings.TrimSpace(location); trimmedLocation != "" {
		baseOpts = append(baseOpts, option.WithEndpoint(fmt.Sprintf("%s-aiplatform.googleapis.com:443", trimmedLocation)))
	}
	if strings.TrimSpace(userAgent) != "" {
		baseOpts = append(baseOpts, option.WithUserAgent(strings.TrimSpace(userAgent)))
	}

	return baseOpts, nil
}
