package worker

import (
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/msteams/internal/config"
)

func TestResolvePath(t *testing.T) {
	params := map[string]any{
		"teamId":     "team:123",
		"channel_id": "chan/456",
		"messageId":  "msg-789",
		"state":      "active",
	}
	pathValue, cleaned, err := resolvePath("/teams/{team_id}/channels/{channel_id}/messages/{message_id}", params, []string{"team_id", "channel_id", "message_id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pathValue != "/teams/team:123/channels/chan%2F456/messages/msg-789" {
		t.Fatalf("unexpected path: %s", pathValue)
	}
	if _, ok := cleaned["teamId"]; ok {
		t.Fatalf("expected team param to be removed")
	}
	if _, ok := cleaned["channel_id"]; ok {
		t.Fatalf("expected channel param to be removed")
	}
	if _, ok := cleaned["messageId"]; ok {
		t.Fatalf("expected message param to be removed")
	}
	if cleaned["state"] != "active" {
		t.Fatalf("expected state to remain in params")
	}
}

func TestNormalizeParams(t *testing.T) {
	params := map[string]any{
		"teamId":      "t1",
		"channelId":   "c1",
		"contentType": "text",
	}
	normalized := normalizeParams(params)
	if normalized["team_id"] != "t1" {
		t.Fatalf("expected team_id to be set")
	}
	if normalized["channel_id"] != "c1" {
		t.Fatalf("expected channel_id to be set")
	}
	if normalized["content_type"] != "text" {
		t.Fatalf("expected content_type to be set")
	}
}

func TestEnsureMessageBody(t *testing.T) {
	params := map[string]any{"content": "Hello", "content_type": "text"}
	out := ensureMessageBody(params)
	body, ok := out["body"].(map[string]any)
	if !ok {
		t.Fatalf("expected body to be created")
	}
	if body["content"] != "Hello" {
		t.Fatalf("expected content to be set")
	}
	if body["contentType"] != "text" {
		t.Fatalf("expected contentType to be set")
	}
	if _, ok := out["content"]; ok {
		t.Fatalf("expected content to be removed")
	}
}

func TestEnforcePolicies(t *testing.T) {
	profile := config.Profile{AllowedTeams: []string{"team-*"}}
	if err := enforceTeamPolicy(profile, "team-123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := enforceTeamPolicy(profile, "other"); err == nil {
		t.Fatalf("expected error for disallowed team")
	}

	profile = config.Profile{DeniedChannels: []string{"channel-9"}}
	if err := enforceChannelPolicy(profile, "channel-9"); err == nil {
		t.Fatalf("expected error for denied channel")
	}
}

func TestValidateParams(t *testing.T) {
	params := map[string]any{"teamId": "t1"}
	if err := validateParams(params, []string{"team|team_id|teamId"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateParams(map[string]any{}, []string{"team"}); err == nil {
		t.Fatalf("expected error for missing param")
	}
}

func TestResolveSecret(t *testing.T) {
	os.Setenv("MSTEAMS_TEST_TOKEN", "env-token")
	defer os.Unsetenv("MSTEAMS_TEST_TOKEN")

	if got := resolveSecret("value-token", "MSTEAMS_TEST_TOKEN"); got != "env-token" {
		t.Fatalf("expected env token, got %q", got)
	}
	os.Unsetenv("MSTEAMS_TEST_TOKEN")
	if got := resolveSecret("value-token", "MSTEAMS_TEST_TOKEN"); got != "value-token" {
		t.Fatalf("expected value token, got %q", got)
	}
}
