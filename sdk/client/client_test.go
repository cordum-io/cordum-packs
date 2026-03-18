package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildTLSTransportNil(t *testing.T) {
	transport := BuildTLSTransport(TLSOptions{})
	if transport != nil {
		t.Fatal("expected nil transport for zero-value TLS options")
	}
}

func TestBuildTLSTransportInsecure(t *testing.T) {
	transport := BuildTLSTransport(TLSOptions{InsecureSkipVerify: true})
	if transport == nil {
		t.Fatal("expected transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLS client config")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected insecure skip verify")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS min version 1.2, got %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestBuildTLSTransportWithCA(t *testing.T) {
	caPath := writeTestCA(t, t.TempDir())

	transport := BuildTLSTransport(TLSOptions{CACertPath: caPath})
	if transport == nil {
		t.Fatal("expected transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLS client config")
	}
	if transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected custom root CA pool")
	}
}

func TestBuildTLSTransportErrBadCA(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "bad-ca.crt")
	if err := os.WriteFile(badCA, []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("write bad ca: %v", err)
	}

	transport, err := BuildTLSTransportErr(TLSOptions{CACertPath: badCA})
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
	if transport != nil {
		t.Fatal("expected nil transport on error")
	}
}

func TestNewWithTLSAppliesTransport(t *testing.T) {
	caPath := writeTestCA(t, t.TempDir())

	client := NewWithTLS("https://example.com", "key", TLSOptions{CACertPath: caPath})
	if client.HTTPClient == nil {
		t.Fatal("expected HTTP client")
	}
	if client.HTTPClient.Transport == nil {
		t.Fatal("expected custom transport")
	}
}

func TestNewUsesEnvTLSConfig(t *testing.T) {
	caPath := writeTestCA(t, t.TempDir())
	t.Setenv("CORDUM_TLS_CA", caPath)
	t.Setenv("CORDUM_TLS_INSECURE", "")

	client := New("https://example.com", "key")
	if client.HTTPClient == nil {
		t.Fatal("expected HTTP client")
	}
	transport, ok := client.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.HTTPClient.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected env-driven TLS config with custom root CAs")
	}
}

func TestNewWithTLSErrMissingCA(t *testing.T) {
	_, err := NewWithTLSErr("https://example.com", "key", TLSOptions{CACertPath: filepath.Join(t.TempDir(), "missing.crt")})
	if err == nil {
		t.Fatal("expected error")
	}
}

func writeTestCA(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	path := filepath.Join(dir, "ca.crt")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}

	return path
}
