package runtime

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	envCordumTLSCA       = "CORDUM_TLS_CA"
	envCordumTLSInsecure = "CORDUM_TLS_INSECURE"

	envNATSTLSCA         = "NATS_TLS_CA"
	envNATSTLSCert       = "NATS_TLS_CERT"
	envNATSTLSKey        = "NATS_TLS_KEY"
	envNATSTLSInsecure   = "NATS_TLS_INSECURE"
	envNATSTLSServerName = "NATS_TLS_SERVER_NAME"

	envRedisTLSCA         = "REDIS_TLS_CA"
	envRedisTLSCert       = "REDIS_TLS_CERT"
	envRedisTLSKey        = "REDIS_TLS_KEY"
	envRedisTLSInsecure   = "REDIS_TLS_INSECURE"
	envRedisTLSServerName = "REDIS_TLS_SERVER_NAME"
)

var defaultTLSCAPaths = []string{
	"/etc/cordum/tls/ca/ca.crt",
	"./certs/ca/ca.crt",
}

type tlsEnvConfig struct {
	label               string
	caEnv               string
	fallbackCAEnv       string
	certEnv             string
	keyEnv              string
	insecureEnv         string
	fallbackInsecureEnv string
	serverNameEnv       string
}

// TLSConfigFromEnv builds a [tls.Config] from CORDUM_TLS_* environment
// variables, falling back to well-known CA certificate paths when no explicit
// CA path is provided. It returns (nil, nil) when no custom TLS configuration
// is required so callers can use the platform default system certificate pool.
func TLSConfigFromEnv() (*tls.Config, error) {
	return tlsConfigFromEnv(tlsEnvConfig{
		label:       "cordum",
		caEnv:       envCordumTLSCA,
		insecureEnv: envCordumTLSInsecure,
	})
}

// NATSTLSConfigFromEnv builds a [tls.Config] from NATS_TLS_* environment
// variables, falling back to CORDUM_TLS_CA / CORDUM_TLS_INSECURE and then the
// shared well-known CA certificate paths.
func NATSTLSConfigFromEnv() (*tls.Config, error) {
	return tlsConfigFromEnv(tlsEnvConfig{
		label:               "nats",
		caEnv:               envNATSTLSCA,
		fallbackCAEnv:       envCordumTLSCA,
		certEnv:             envNATSTLSCert,
		keyEnv:              envNATSTLSKey,
		insecureEnv:         envNATSTLSInsecure,
		fallbackInsecureEnv: envCordumTLSInsecure,
		serverNameEnv:       envNATSTLSServerName,
	})
}

// RedisTLSConfigFromEnv builds a [tls.Config] from REDIS_TLS_* environment
// variables, falling back to CORDUM_TLS_CA / CORDUM_TLS_INSECURE and then the
// shared well-known CA certificate paths.
func RedisTLSConfigFromEnv() (*tls.Config, error) {
	return tlsConfigFromEnv(tlsEnvConfig{
		label:               "redis",
		caEnv:               envRedisTLSCA,
		fallbackCAEnv:       envCordumTLSCA,
		certEnv:             envRedisTLSCert,
		keyEnv:              envRedisTLSKey,
		insecureEnv:         envRedisTLSInsecure,
		fallbackInsecureEnv: envCordumTLSInsecure,
		serverNameEnv:       envRedisTLSServerName,
	})
}

func tlsConfigFromEnv(cfg tlsEnvConfig) (*tls.Config, error) {
	caPath := resolveTLSPath(cfg.caEnv)
	if caPath == "" {
		caPath = resolveTLSPath(cfg.fallbackCAEnv)
	}
	if caPath == "" {
		caPath = discoverTLSCAPath()
	}

	certPath := resolveTLSPath(cfg.certEnv)
	keyPath := resolveTLSPath(cfg.keyEnv)
	serverName := strings.TrimSpace(os.Getenv(cfg.serverNameEnv))
	insecure := parseBoolEnv(cfg.insecureEnv) || parseBoolEnv(cfg.fallbackInsecureEnv)

	if caPath == "" && certPath == "" && keyPath == "" && serverName == "" && !insecure {
		return nil, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // minimum TLS version is enforced.
	if serverName != "" {
		tlsCfg.ServerName = serverName
	}
	if insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // operator opt-in for dev/testing only.
	}
	if caPath != "" {
		pool, err := certPoolFromPEM(caPath)
		if err != nil {
			return nil, fmt.Errorf("%s tls ca: %w", cfg.label, err)
		}
		tlsCfg.RootCAs = pool
	}
	if certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return nil, fmt.Errorf("%s tls cert/key must be set together", cfg.label)
		}
		cert, err := tls.LoadX509KeyPair(filepath.Clean(certPath), filepath.Clean(keyPath))
		if err != nil {
			return nil, fmt.Errorf("%s tls keypair: %w", cfg.label, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func resolveTLSPath(envKey string) string {
	if strings.TrimSpace(envKey) == "" {
		return ""
	}
	path := strings.TrimSpace(os.Getenv(envKey))
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func discoverTLSCAPath() string {
	for _, candidate := range defaultTLSCAPaths {
		path := filepath.Clean(candidate)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		return path
	}
	return ""
}

func certPoolFromPEM(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-controlled certificate path.
	if err != nil {
		return nil, fmt.Errorf("read ca cert %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("parse ca cert %s: no valid PEM certificates found", path)
	}
	return pool, nil
}

func parseBoolEnv(key string) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	value := strings.TrimSpace(os.Getenv(key))
	return value == "1" || strings.EqualFold(value, "true")
}
