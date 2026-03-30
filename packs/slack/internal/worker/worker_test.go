package worker

import (
	"strings"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/slack/internal/config"
)

func TestValidateParams(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]any
		required []string
		wantErr  bool
	}{
		{
			name:     "all required keys present",
			params:   map[string]any{"channel": "C123", "ts": "1234567890.123456"},
			required: []string{"channel", "ts"},
			wantErr:  false,
		},
		{
			name:     "missing required key",
			params:   map[string]any{"channel": "C123"},
			required: []string{"channel", "ts"},
			wantErr:  true,
		},
		{
			name:     "empty string value fails",
			params:   map[string]any{"channel": "  "},
			required: []string{"channel"},
			wantErr:  true,
		},
		{
			name:     "empty slice value fails",
			params:   map[string]any{"users": []any{}},
			required: []string{"users"},
			wantErr:  true,
		},
		{
			name:     "nil params with required keys fails",
			params:   nil,
			required: []string{"channel"},
			wantErr:  true,
		},
		{
			name:     "no required keys always passes",
			params:   map[string]any{},
			required: nil,
			wantErr:  false,
		},
		{
			name:     "nil params no required keys passes",
			params:   nil,
			required: nil,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateParams(tt.params, tt.required)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnforceChannelPolicy(t *testing.T) {
	tests := []struct {
		name     string
		profile  config.Profile
		channels []string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "no policy passes",
			profile:  config.Profile{},
			channels: []string{"C123", "C456"},
			wantErr:  false,
		},
		{
			name:     "allowed channels matching channel passes",
			profile:  config.Profile{AllowedChannels: []string{"C123", "C456"}},
			channels: []string{"C123"},
			wantErr:  false,
		},
		{
			name:     "allowed channels non-matching channel fails",
			profile:  config.Profile{AllowedChannels: []string{"C123", "C456"}},
			channels: []string{"C999"},
			wantErr:  true,
			errMsg:   "channel not allowed",
		},
		{
			name:     "denied channels matching channel fails",
			profile:  config.Profile{DeniedChannels: []string{"C999"}},
			channels: []string{"C999"},
			wantErr:  true,
			errMsg:   "channel denied",
		},
		{
			name:     "denied channels non-matching channel passes",
			profile:  config.Profile{DeniedChannels: []string{"C999"}},
			channels: []string{"C123"},
			wantErr:  false,
		},
		{
			name:     "empty channels list always passes",
			profile:  config.Profile{AllowedChannels: []string{"C123"}},
			channels: []string{},
			wantErr:  false,
		},
		{
			name:     "allowed and denied combined deny takes precedence",
			profile:  config.Profile{AllowedChannels: []string{"C123"}, DeniedChannels: []string{"C123"}},
			channels: []string{"C123"},
			wantErr:  true,
			errMsg:   "channel denied",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := enforceChannelPolicy(tt.profile, tt.channels)
			if (err != nil) != tt.wantErr {
				t.Errorf("enforceChannelPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("enforceChannelPolicy() error = %v, want message containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestEnforceActionPolicy(t *testing.T) {
	tests := []struct {
		name    string
		profile config.Profile
		action  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "no policy passes",
			profile: config.Profile{},
			action:  "chat.postMessage",
			wantErr: false,
		},
		{
			name:    "allow list with matching action passes",
			profile: config.Profile{AllowActions: []string{"chat.postMessage", "conversations.list"}},
			action:  "chat.postMessage",
			wantErr: false,
		},
		{
			name:    "allow list without matching action fails",
			profile: config.Profile{AllowActions: []string{"chat.postMessage"}},
			action:  "conversations.list",
			wantErr: true,
			errMsg:  "action not allowed",
		},
		{
			name:    "deny list with matching action fails",
			profile: config.Profile{DenyActions: []string{"chat.delete"}},
			action:  "chat.delete",
			wantErr: true,
			errMsg:  "action denied",
		},
		{
			name:    "deny list without matching action passes",
			profile: config.Profile{DenyActions: []string{"chat.delete"}},
			action:  "chat.postMessage",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := enforceActionPolicy(tt.profile, tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("enforceActionPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("enforceActionPolicy() error = %v, want message containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestExtractChannels(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		keys   []string
		want   []string
	}{
		{
			name:   "single channel string value",
			params: map[string]any{"channel": "C123"},
			keys:   []string{"channel"},
			want:   []string{"C123"},
		},
		{
			name:   "comma-separated channels",
			params: map[string]any{"channel": "C123,C456,C789"},
			keys:   []string{"channel"},
			want:   []string{"C123", "C456", "C789"},
		},
		{
			name:   "array of channels",
			params: map[string]any{"channel": []any{"C123", "C456"}},
			keys:   []string{"channel"},
			want:   []string{"C123", "C456"},
		},
		{
			name:   "custom keys parameter",
			params: map[string]any{"target": "C123", "other": "ignored"},
			keys:   []string{"target"},
			want:   []string{"C123"},
		},
		{
			name:   "deduplication across keys",
			params: map[string]any{"channel": "C123", "channels": []string{"C123", "C456"}},
			keys:   []string{"channel", "channels"},
			want:   []string{"C123", "C456"},
		},
		{
			name:   "nil keys uses defaults",
			params: map[string]any{"channel": "C123"},
			keys:   nil,
			want:   []string{"C123"},
		},
		{
			name:   "no matching keys returns nil",
			params: map[string]any{"unrelated": "value"},
			keys:   []string{"channel"},
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractChannels(tt.params, tt.keys)
			if len(got) != len(tt.want) {
				t.Fatalf("extractChannels() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("extractChannels()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestResolveSecret(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		envKey   string
		envValue string
		setEnv   bool
		want     string
	}{
		{
			name:     "env var set takes priority",
			value:    "fallback-token",
			envKey:   "TEST_RESOLVE_SECRET_TOKEN",
			envValue: "env-token",
			setEnv:   true,
			want:     "env-token",
		},
		{
			name:   "env var not set falls back to value",
			value:  "fallback-token",
			envKey: "TEST_RESOLVE_SECRET_MISSING",
			setEnv: false,
			want:   "fallback-token",
		},
		{
			name:   "both empty returns empty",
			value:  "",
			envKey: "",
			setEnv: false,
			want:   "",
		},
		{
			name:     "env var set to whitespace falls back to value",
			value:    "fallback-token",
			envKey:   "TEST_RESOLVE_SECRET_WS",
			envValue: "   ",
			setEnv:   true,
			want:     "fallback-token",
		},
		{
			name:   "empty env key with value returns value",
			value:  "direct-token",
			envKey: "",
			setEnv: false,
			want:   "direct-token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv && tt.envKey != "" {
				t.Setenv(tt.envKey, tt.envValue)
			}
			got := resolveSecret(tt.value, tt.envKey)
			if got != tt.want {
				t.Errorf("resolveSecret() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateInlineAuth(t *testing.T) {
	tests := []struct {
		name         string
		auth         InlineAuth
		allowed      bool
		allowSecrets bool
		wantErr      bool
		errMsg       string
	}{
		{
			name:         "no auth passes regardless",
			auth:         InlineAuth{},
			allowed:      false,
			allowSecrets: false,
			wantErr:      false,
		},
		{
			name:         "auth with allowed true passes",
			auth:         InlineAuth{TokenEnv: "SOME_VAR"},
			allowed:      true,
			allowSecrets: false,
			wantErr:      false,
		},
		{
			name:         "auth with allowed false fails",
			auth:         InlineAuth{TokenEnv: "SOME_VAR"},
			allowed:      false,
			allowSecrets: false,
			wantErr:      true,
			errMsg:       "inline auth disabled",
		},
		{
			name:         "token with allowSecrets false fails",
			auth:         InlineAuth{Token: "xoxb-secret"},
			allowed:      true,
			allowSecrets: false,
			wantErr:      true,
			errMsg:       "inline secrets disabled",
		},
		{
			name:         "token_env with allowSecrets false passes",
			auth:         InlineAuth{TokenEnv: "MY_TOKEN_ENV"},
			allowed:      true,
			allowSecrets: false,
			wantErr:      false,
		},
		{
			name:         "token with allowSecrets true passes",
			auth:         InlineAuth{Token: "xoxb-secret"},
			allowed:      true,
			allowSecrets: true,
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInlineAuth(tt.auth, tt.allowed, tt.allowSecrets)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateInlineAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateInlineAuth() error = %v, want message containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestHasParam(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		key    string
		want   bool
	}{
		{
			name:   "key exists with string value",
			params: map[string]any{"channel": "C123"},
			key:    "channel",
			want:   true,
		},
		{
			name:   "key exists with empty string",
			params: map[string]any{"channel": ""},
			key:    "channel",
			want:   false,
		},
		{
			name:   "key missing",
			params: map[string]any{"other": "value"},
			key:    "channel",
			want:   false,
		},
		{
			name:   "key with number value",
			params: map[string]any{"limit": 42},
			key:    "limit",
			want:   true,
		},
		{
			name:   "key with empty slice",
			params: map[string]any{"users": []any{}},
			key:    "users",
			want:   false,
		},
		{
			name:   "key with populated slice",
			params: map[string]any{"users": []any{"U1", "U2"}},
			key:    "users",
			want:   true,
		},
		{
			name:   "key with whitespace-only string",
			params: map[string]any{"channel": "   "},
			key:    "channel",
			want:   false,
		},
		{
			name:   "key with bool value",
			params: map[string]any{"unfurl_links": true},
			key:    "unfurl_links",
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasParam(tt.params, tt.key)
			if got != tt.want {
				t.Errorf("hasParam() = %v, want %v", got, tt.want)
			}
		})
	}
}
