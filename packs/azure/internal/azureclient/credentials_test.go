package azureclient

import (
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/cordum-io/cordum-packs/packs/azure/internal/config"
)

func TestResolveSubscriptionID(t *testing.T) {
	tests := []struct {
		name     string
		override string
		profile  config.Profile
		want     string
	}{
		{"override wins", "sub-override", config.Profile{SubscriptionID: "sub-profile"}, "sub-override"},
		{"profile fallback", "", config.Profile{SubscriptionID: "sub-profile"}, "sub-profile"},
		{"empty both", "", config.Profile{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveSubscriptionID(tt.override, tt.profile)
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestResolveResourceGroup(t *testing.T) {
	tests := []struct {
		name     string
		override string
		profile  config.Profile
		want     string
	}{
		{"override wins", "rg-override", config.Profile{ResourceGroup: "rg-profile"}, "rg-override"},
		{"profile fallback", "", config.Profile{ResourceGroup: "rg-profile"}, "rg-profile"},
		{"empty both", "", config.Profile{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveResourceGroup(tt.override, tt.profile)
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestProfileIsActionAllowed(t *testing.T) {
	tests := []struct {
		name    string
		profile config.Profile
		action  string
		want    bool
	}{
		{"no restrictions", config.Profile{}, "blob.get", true},
		{"deny blocks", config.Profile{DenyActions: []string{"blob.delete"}}, "blob.delete", false},
		{"deny allows other", config.Profile{DenyActions: []string{"blob.delete"}}, "blob.get", true},
		{"allow permits", config.Profile{AllowActions: []string{"blob.*"}}, "blob.get", true},
		{"allow blocks non-match", config.Profile{AllowActions: []string{"blob.*"}}, "compute.list_vms", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.profile.IsActionAllowed(tt.action)
			if got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestNewCredentialConcurrentProfiles(t *testing.T) {
	// Set up two distinct secret env vars (t.Setenv auto-restores)
	t.Setenv("TEST_SECRET_A", "secret-aaa")
	t.Setenv("TEST_SECRET_B", "secret-bbb")

	profileA := config.Profile{
		TenantID:        "tenant-a",
		ClientID:        "client-a",
		ClientSecretEnv: "TEST_SECRET_A",
	}
	profileB := config.Profile{
		TenantID:        "tenant-b",
		ClientID:        "client-b",
		ClientSecretEnv: "TEST_SECRET_B",
	}

	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(2)

	errsCh := make(chan error, iterations*2)

	run := func(p config.Profile) {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			cred, err := NewCredential(p)
			if err != nil {
				errsCh <- err
				continue
			}
			if cred == nil {
				t.Error("expected non-nil credential")
				continue
			}
			if _, ok := cred.(*azidentity.ClientSecretCredential); !ok {
				t.Errorf("expected *azidentity.ClientSecretCredential, got %T", cred)
			}
		}
	}

	go run(profileA)
	go run(profileB)
	wg.Wait()
	close(errsCh)

	for err := range errsCh {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewCredentialDefaultFallback(t *testing.T) {
	// Empty profile — no explicit creds — should fall back to DefaultAzureCredential
	profile := config.Profile{}

	cred, err := NewCredential(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if _, ok := cred.(*azidentity.DefaultAzureCredential); !ok {
		t.Errorf("expected *azidentity.DefaultAzureCredential, got %T", cred)
	}
}

func TestNewCredentialPartialExplicit(t *testing.T) {
	// TenantID + ClientID present but no secret — should fall back to DefaultAzureCredential
	profile := config.Profile{
		TenantID: "tenant-partial",
		ClientID: "client-partial",
		// ClientSecretEnv is empty — ResolveClientSecret() returns ""
	}

	cred, err := NewCredential(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if _, ok := cred.(*azidentity.DefaultAzureCredential); !ok {
		t.Errorf("expected *azidentity.DefaultAzureCredential, got %T", cred)
	}
}
