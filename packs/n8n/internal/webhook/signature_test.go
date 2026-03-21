package webhook

import "testing"

func TestVerifySignature(t *testing.T) {
	secret := "secret"
	body := []byte(`{"ok":true}`)
	sig := ComputeSignature(secret, body)
	if err := VerifySignature(secret, body, "sha256="+sig); err != nil {
		t.Fatalf("expected signature valid: %v", err)
	}
}

func TestVerifySignatureRejectsInvalidValue(t *testing.T) {
	if err := VerifySignature("secret", []byte("payload"), "bad-signature"); err == nil {
		t.Fatal("expected invalid signature error")
	}
}
