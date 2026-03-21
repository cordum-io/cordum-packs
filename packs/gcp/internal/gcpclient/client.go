package gcpclient

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/option"

	"github.com/cordum-io/cordum-packs/packs/gcp/internal/config"
)

// RequestConfig captures the resolved project/location/profile settings for a worker request.
type RequestConfig struct {
	Profile   config.Profile
	ProjectID string
	Location  string
	Options   []option.ClientOption
}

// ResolveRequestConfig resolves profile, project restrictions, location, and client options.
func ResolveRequestConfig(ctx context.Context, cfg config.Config, profileName, projectOverride, locationOverride string) (RequestConfig, error) {
	profile := cfg.ResolveProfile(profileName)
	projectID := profile.ResolveProjectID(strings.TrimSpace(projectOverride), cfg.DefaultProjectID)
	if projectID == "" {
		return RequestConfig{}, fmt.Errorf("project_id is required")
	}
	if !profile.IsProjectAllowed(projectID) {
		return RequestConfig{}, fmt.Errorf("project %q is not allowed by profile %q", projectID, profile.Name)
	}

	clientOptions, err := BuildClientOptions(ctx, profile, cfg.UserAgent)
	if err != nil {
		return RequestConfig{}, err
	}

	return RequestConfig{
		Profile:   profile,
		ProjectID: projectID,
		Location:  profile.ResolveLocation(strings.TrimSpace(locationOverride), cfg.DefaultLocation),
		Options:   clientOptions,
	}, nil
}
