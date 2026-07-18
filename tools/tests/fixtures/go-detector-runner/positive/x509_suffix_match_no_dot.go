// Pattern 41 — POSITIVE fixture for
//   go.crypto.x509.suffix_match_no_dot_anchor
//
// Mirrors Swival #038 — Go crypto/x509 name-constraint match
// accepting label-prefix violations like
// HasSuffix("evilexample.com", "example.com").
package fixture

import (
	"strings"
)

// BUG: HasSuffix without a dot anchor — `evilexample.com` matches
// `example.com` constraint and bypasses the name constraint.
func MatchEmailDomain(addr string, constraint string) bool {
	if strings.HasSuffix(addr, constraint) {
		return true
	}
	return false
}

// BUG: same shape but using HasPrefix on a reversed input — still no
// dot anchor.
func MatchURIPrefix(uri string, prefix string) bool {
	return strings.HasPrefix(uri, prefix)
}

// BUG: bytes.HasSuffix variant — same label-boundary bug class.
func MatchDNSAlt(name string, suffix string) bool {
	if strings.HasSuffix(name, suffix) {
		return true
	}
	return false
}
