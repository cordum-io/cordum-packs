package main

import (
	"strings"
	"testing"
)

func TestLoadConfigUnsignedOptIn(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        bool
		wantError   bool
	}{
		{"default", "", false, false},
		{"explicit true", "true", true, false},
		{"explicit false", "false", false, false},
		{"invalid", "enabled", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CORDUM_MCP_ALLOW_UNSIGNED", tc.value)
			cfg, err := loadConfig()
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "CORDUM_MCP_ALLOW_UNSIGNED") {
					t.Fatalf("expected explicit boolean configuration error, got %v", err)
				}
				return
			}
			if err != nil || cfg.AllowUnsigned != tc.want {
				t.Fatalf("AllowUnsigned=%v error=%v, want %v", cfg.AllowUnsigned, err, tc.want)
			}
		})
	}
}
