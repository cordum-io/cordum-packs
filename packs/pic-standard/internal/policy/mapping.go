package policy

import (
	"strings"

	"github.com/cordum-io/cordum-packs/packs/pic-standard/internal/picclient"
)

// Output is the Cordum workflow output for the pic-standard.verify topic.
// All fields are required per PicVerifyOutput.json schema.
// Impact and Reason are nullable (any typed: string or nil → JSON null).
type Output struct {
	Allowed bool   `json:"allowed"`
	EvalMs  int    `json:"eval_ms"`
	Next    string `json:"next"`
	Impact  any    `json:"impact"` // string or nil
	Reason  any    `json:"reason"` // string or nil
}

// MapResult converts a PIC bridge VerifyResponse into a Cordum workflow Output.
// Use when no impact classification is available.
//
// Routing:
//   - allowed=false → next="fail"
//   - allowed=true  → next="proceed"
func MapResult(resp picclient.VerifyResponse) Output {
	out := Output{
		Allowed: resp.Allowed,
		EvalMs:  resp.EvalMs,
		Impact:  nil,
		Reason:  nil,
	}

	if !resp.Allowed {
		out.Next = "fail"
		if resp.Error != nil {
			if msg := strings.TrimSpace(resp.Error.Message); msg != "" {
				out.Reason = msg
			} else if code := strings.TrimSpace(resp.Error.Code); code != "" {
				out.Reason = "code:" + code
			}
		}
		return out
	}

	out.Next = "proceed"
	return out
}

// MapResultWithImpact converts a PIC bridge VerifyResponse into a Cordum
// workflow Output, with an impact classification for approval routing.
//
// Routing:
//   - allowed=false                               → next="fail"
//   - allowed=true + impact in approvalImpacts     → next="require_approval"
//   - allowed=true otherwise                       → next="proceed"
func MapResultWithImpact(resp picclient.VerifyResponse, impact string, approvalImpacts []string) Output {
	out := MapResult(resp)

	impact = strings.TrimSpace(impact)
	if impact != "" {
		out.Impact = impact
	}

	if out.Allowed && impact != "" && containsFold(approvalImpacts, impact) {
		out.Next = "require_approval"
	}

	return out
}

func containsFold(list []string, val string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), val) {
			return true
		}
	}
	return false
}
