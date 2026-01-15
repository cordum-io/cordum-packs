package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cordum-io/cordum-packs/packs/webhooks/internal/config"
)

func TestVerifySignatureHMACSHA256(t *testing.T) {
	secret := "secret"
	body := []byte("payload")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "http://example.com", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256="+sig)

	route := config.Route{SignatureType: "hmac_sha256", SignatureHeader: "X-Hub-Signature-256"}
	if err := verifySignature(route, req, body, secret); err != nil {
		t.Fatalf("expected signature valid: %v", err)
	}
}

func TestVerifySignatureToken(t *testing.T) {
	secret := "token"
	req := httptest.NewRequest(http.MethodPost, "http://example.com", nil)
	req.Header.Set("X-Webhook-Token", secret)

	route := config.Route{SignatureType: "token", TokenHeader: "X-Webhook-Token"}
	if err := verifySignature(route, req, nil, secret); err != nil {
		t.Fatalf("expected token valid: %v", err)
	}
}

func TestResolveSecret(t *testing.T) {
	os.Setenv("WEBHOOK_TEST_SECRET", "env-secret")
	defer os.Unsetenv("WEBHOOK_TEST_SECRET")

	if got := resolveSecret("value-secret", "WEBHOOK_TEST_SECRET"); got != "env-secret" {
		t.Fatalf("expected env secret, got %q", got)
	}
	os.Unsetenv("WEBHOOK_TEST_SECRET")
	if got := resolveSecret("value-secret", "WEBHOOK_TEST_SECRET"); got != "value-secret" {
		t.Fatalf("expected value secret, got %q", got)
	}
}
