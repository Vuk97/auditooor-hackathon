// Pattern 33 — POSITIVE fixture for
//   go.crypto.parse.negative_or_zero_int_unchecked
//
// Mirrors Swival #060/#061/#062/#063 — parsed integer fields flow into
// downstream control without a lower-bound (>=0 / >0) guard. RFC5280
// x509 policy fields ("requireExplicitPolicy", "inhibitPolicyMapping",
// etc.) MUST be non-negative; accepting negative or zero values lets a
// crafted certificate panic the path-validation routine or bypass the
// policy mapping.
package fixture

import (
	"strconv"
)

// Stub cryptobyte-shaped reader. Production code uses
// `golang.org/x/crypto/cryptobyte`; we model the same call shape so the
// detector can fire without importing the real package.
type cbString struct{}

func (s *cbString) ReadASN1Int64() (int64, bool)            { return 0, true }
func (s *cbString) ReadASN1Integer(out *int64) bool         { return true }
func (s *cbString) ReadInt32() (int32, bool)                { return 0, true }

// BUG: cryptobyte ASN1 int reader yields a value that flows downstream
// without any `requireExplicitPolicy <= 0` guard.
func ParsePolicyConstraints(s *cbString) (int64, error) {
	requireExplicitPolicy, _ := s.ReadASN1Int64()
	// requireExplicitPolicy is used downstream as a depth bound.
	return requireExplicitPolicy + 1, nil
}

// BUG: strconv.ParseInt yields a count that is consumed without a guard
// against zero / negative values.
func ParseIterCount(in string) []byte {
	iter, _ := strconv.ParseInt(in, 10, 32)
	out := []byte{}
	for j := int64(0); j < iter; j++ {
		out = append(out, byte(j))
	}
	return out
}

// BUG: int32 reader yields a value used directly as an array index.
// No bounds guard.
func ReadOpcode(s *cbString) int32 {
	opcode, _ := s.ReadInt32()
	return opcode
}
