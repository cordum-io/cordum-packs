package policyconstraints

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	agentv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	constraintsEnv = "CORDUM_POLICY_CONSTRAINTS"
	maxArtifactEnv = "CORDUM_MAX_ARTIFACT_BYTES"
	redactionEnv   = "CORDUM_REDACTION_LEVEL"
)

func Parse(env map[string]string) (*agentv1.PolicyConstraints, error) {
	if env == nil {
		return nil, nil
	}
	raw := strings.TrimSpace(env[constraintsEnv])
	if raw == "" {
		return nil, nil
	}
	var constraints agentv1.PolicyConstraints
	if err := protojson.Unmarshal([]byte(raw), &constraints); err != nil {
		return nil, err
	}
	return &constraints, nil
}

func MaxArtifactBytes(env map[string]string) int64 {
	if env == nil {
		return 0
	}
	val := strings.TrimSpace(env[maxArtifactEnv])
	if val == "" {
		return 0
	}
	parsed, err := strconv.ParseInt(val, 10, 64)
	if err != nil || parsed < 0 {
		return 0
	}
	return parsed
}

func RedactionLevel(env map[string]string) string {
	if env == nil {
		return ""
	}
	return strings.TrimSpace(env[redactionEnv])
}

func HostAllowed(constraints *agentv1.PolicyConstraints, rawURL string) (bool, error) {
	if constraints == nil || constraints.GetSandbox() == nil {
		return true, nil
	}
	allowlist := constraints.GetSandbox().GetNetworkAllowlist()
	if len(allowlist) == 0 {
		return true, nil
	}
	if strings.TrimSpace(rawURL) == "" {
		return false, errors.New("missing webhook url")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false, err
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return false, errors.New("missing host in webhook url")
	}
	for _, entry := range allowlist {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true, nil
		}
		if strings.HasPrefix(entry, "*.") {
			suffix := strings.TrimPrefix(entry, "*.")
			if strings.HasSuffix(host, suffix) {
				return true, nil
			}
			continue
		}
		if host == entry {
			return true, nil
		}
	}
	return false, nil
}
