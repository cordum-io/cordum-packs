package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const SignatureHeader = "X-N8N-Signature"

// ComputeSignature returns the hex HMAC-SHA256 signature for the body.
func ComputeSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature validates the provided HMAC-SHA256 signature.
func VerifySignature(secret string, body []byte, provided string) error {
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("webhook secret required")
	}
	provided = normalizeSignature(provided)
	if provided == "" {
		return fmt.Errorf("signature missing")
	}
	expected := ComputeSignature(secret, body)
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func normalizeSignature(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "=") {
		parts := strings.SplitN(value, "=", 2)
		return strings.TrimSpace(parts[1])
	}
	return value
}
