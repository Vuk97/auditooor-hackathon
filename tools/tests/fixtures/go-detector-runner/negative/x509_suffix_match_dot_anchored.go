// Pattern 41 — NEGATIVE fixture: every suffix match is anchored by a
// leading "." or routed through an IDNA / publicsuffix helper.
// Detector must NOT fire.
package fixture

import (
	"strings"
)

// SAFE: the constraint is dot-anchored before the suffix check, so
// `evilexample.com` no longer matches `.example.com`.
func MatchEmailDomain(addr string, constraint string) bool {
	anchored := "." + constraint
	if strings.HasSuffix(addr, anchored) {
		return true
	}
	return false
}

// SAFE: routes through `matchHostnames` — a documented helper that
// does label-aware matching.
func MatchURIPrefix(uri string, prefix string) bool {
	return matchHostnames(uri, prefix)
}

// SAFE: explicit bytewise label-boundary check.
func MatchDNSAlt(name string, suffix string) bool {
	if strings.HasSuffix(name, suffix) {
		idx := len(name) - len(suffix) - 1
		if idx < 0 || name[idx] == '.' {
			return true
		}
	}
	return false
}

func matchHostnames(a, b string) bool {
	return false
}
