package scheduler

import (
	"testing"

	"github.com/cordum-io/cordum-packs/packs/cron-triggers/internal/config"
)

func TestHasSecondsField(t *testing.T) {
	cases := []struct {
		Spec   string
		Expect bool
	}{
		{"0 0 * * *", false},
		{"CRON_TZ=UTC 0 0 * * *", false},
		{"0 0 0 * * *", true},
		{"TZ=UTC 0 0 0 * * *", true},
	}
	for _, c := range cases {
		if got := hasSecondsField(c.Spec); got != c.Expect {
			t.Fatalf("spec %q expected %v got %v", c.Spec, c.Expect, got)
		}
	}
}

func TestWorkflowAllowed(t *testing.T) {
	profile := config.Profile{
		Name:             "default",
		AllowedWorkflows: []string{"hello-pack.*"},
		DeniedWorkflows:  []string{"secret.*"},
	}
	if !workflowAllowed(profile, "hello-pack.echo") {
		t.Fatalf("expected allowed workflow")
	}
	if workflowAllowed(profile, "secret.task") {
		t.Fatalf("expected denied workflow")
	}
}
