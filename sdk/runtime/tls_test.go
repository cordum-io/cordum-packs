package runtime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSConfigFromEnvNone(t *testing.T) {
	t.Setenv("CORDUM_TLS_CA", "")
	t.Setenv("CORDUM_TLS_INSECURE", "")

	workdir := t.TempDir()
	withWorkingDir(t, workdir)

	cfg, err := TLSConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config when no TLS overrides are configured")
	}
}

func TestTLSConfigFromEnvInsecure(t *testing.T) {
	t.Setenv("CORDUM_TLS_CA", "")
	t.Setenv("CORDUM_TLS_INSECURE", "1")

	workdir := t.TempDir()
	withWorkingDir(t, workdir)

	cfg, err := TLSConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected insecure skip verify")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2 minimum, got %d", cfg.MinVersion)
	}
}

func TestTLSConfigFromEnvAutodiscoversFallbackCA(t *testing.T) {
	t.Setenv("CORDUM_TLS_CA", "")
	t.Setenv("CORDUM_TLS_INSECURE", "")

	workdir := t.TempDir()
	caDir := filepath.Join(workdir, "certs", "ca")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	writePEMCertificate(t, filepath.Join(caDir, "ca.crt"), generateCACertificate(t))
	withWorkingDir(t, workdir)

	cfg, err := TLSConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected TLS config from autodiscovered CA")
	}
	if cfg.RootCAs == nil {
		t.Fatal("expected root CA pool")
	}
}

func TestNATSTLSConfigFromEnvUsesCordumCAFallback(t *testing.T) {
	workdir := t.TempDir()
	withWorkingDir(t, workdir)

	caPath, certPath, keyPath := generateTestCerts(t, workdir)
	t.Setenv("CORDUM_TLS_CA", caPath)
	t.Setenv("CORDUM_TLS_INSECURE", "")
	t.Setenv("NATS_TLS_CA", "")
	t.Setenv("NATS_TLS_CERT", certPath)
	t.Setenv("NATS_TLS_KEY", keyPath)
	t.Setenv("NATS_TLS_INSECURE", "")
	t.Setenv("NATS_TLS_SERVER_NAME", "nats.local")

	cfg, err := NATSTLSConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if cfg.RootCAs == nil {
		t.Fatal("expected root CAs")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one client certificate, got %d", len(cfg.Certificates))
	}
	if cfg.ServerName != "nats.local" {
		t.Fatalf("expected server name nats.local, got %s", cfg.ServerName)
	}
}

func TestNATSTLSConfigFromEnvMissingKey(t *testing.T) {
	workdir := t.TempDir()
	withWorkingDir(t, workdir)

	caPath, certPath, _ := generateTestCerts(t, workdir)
	t.Setenv("CORDUM_TLS_CA", caPath)
	t.Setenv("NATS_TLS_CERT", certPath)
	t.Setenv("NATS_TLS_KEY", "")

	_, err := NATSTLSConfigFromEnv()
	if err == nil {
		t.Fatal("expected error when NATS cert is set without key")
	}
}

func TestNewRedisBlobStoreWithTTLAppliesTLSConfig(t *testing.T) {
	workdir := t.TempDir()
	withWorkingDir(t, workdir)

	caPath, _, _ := generateTestCerts(t, workdir)
	t.Setenv("REDIS_TLS_CA", "")
	t.Setenv("CORDUM_TLS_CA", caPath)
	t.Setenv("REDIS_TLS_INSECURE", "")
	t.Setenv("CORDUM_TLS_INSECURE", "")

	store, err := NewRedisBlobStoreWithTTL("rediss://localhost:6379/0", time.Minute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer store.Close()

	if store.client.Options().TLSConfig == nil {
		t.Fatal("expected redis TLS config")
	}
	if store.client.Options().TLSConfig.RootCAs == nil {
		t.Fatal("expected redis custom root CA pool")
	}
}

func withWorkingDir(t *testing.T, dir string) {
	t.Helper()

	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
}

func generateCACertificate(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
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
		t.Fatalf("create CA certificate: %v", err)
	}

	return der
}

func generateTestCerts(t *testing.T, dir string) (string, string, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	caPath := filepath.Join(dir, "ca.crt")
	writePEMCertificate(t, caPath, caDER)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}

	certPath := filepath.Join(dir, "tls.crt")
	writePEMCertificate(t, certPath, clientDER)

	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	keyPath := filepath.Join(dir, "tls.key")
	writePEMBlock(t, keyPath, "PRIVATE KEY", keyDER)

	return caPath, certPath, keyPath
}

func writePEMCertificate(t *testing.T, path string, der []byte) {
	t.Helper()
	writePEMBlock(t, path, "CERTIFICATE", der)
}

func writePEMBlock(t *testing.T, path, blockType string, der []byte) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
}
