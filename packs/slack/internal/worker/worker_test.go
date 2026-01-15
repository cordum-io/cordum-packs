package worker

import (
	"os"
	"reflect"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/slack/internal/config"
)

func TestEncodeQuery(t *testing.T) {
	params := map[string]any{
		"channel": "C123",
		"limit":   10,
		"types":   []string{"public_channel", "private_channel"},
	}
	values := encodeQuery(params)
	if got := values.Get("channel"); got != "C123" {
		t.Fatalf("expected channel, got %q", got)
	}
	if got := values.Get("limit"); got != "10" {
		t.Fatalf("expected limit, got %q", got)
	}
	if got := values.Get("types"); got != "public_channel,private_channel" {
		t.Fatalf("expected types, got %q", got)
	}
}

func TestExtractChannels(t *testing.T) {
	params := map[string]any{
		"channel":  "C123",
		"channels": []string{"C123", "C456"},
	}
	channels := extractChannels(params, nil)
	if !reflect.DeepEqual(channels, []string{"C123", "C456"}) {
		t.Fatalf("unexpected channels: %v", channels)
	}
}

func TestEnforceChannelPolicy(t *testing.T) {
	profile := config.Profile{AllowedChannels: []string{"C1", "C2"}}
	if err := enforceChannelPolicy(profile, []string{"C2"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceChannelPolicy(profile, []string{"C3"}); err == nil {
		t.Fatalf("expected error for disallowed channel")
	}

	profile = config.Profile{DeniedChannels: []string{"C9"}}
	if err := enforceChannelPolicy(profile, []string{"C9"}); err == nil {
		t.Fatalf("expected error for denied channel")
	}
}

func TestResolveSecret(t *testing.T) {
	os.Setenv("SLACK_TEST_TOKEN", "env-token")
	defer os.Unsetenv("SLACK_TEST_TOKEN")

	if got := resolveSecret("value-token", "SLACK_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
	os.Unsetenv("SLACK_TEST_TOKEN")
	if got := resolveSecret("value-token", "SLACK_TEST_TOKEN"); got != "value-token" {
		t.Fatalf("expected value token, got %q", got)
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"channel": "C1"}
	if err := validateParams(params, []string{"channel"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(params, []string{"missing"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}
