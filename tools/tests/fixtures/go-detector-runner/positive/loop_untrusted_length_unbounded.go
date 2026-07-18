// Pattern 36 — POSITIVE fixture for
//   go.crypto.loop.untrusted_length_unbounded
//
// Mirrors Swival #010 / #067 — RFC5280-shape parsers reading a
// length-prefix and walking a buffer that long without sanity-
// checking the length against the remaining input. CVE-2025-22871
// shape: TLS-handshake-style length-prefixed parser allocates and
// then iterates over an attacker-controlled length.
package fixture

import (
	"encoding/binary"
	"strconv"
)

// Stub cryptobyte-shaped reader.
type cbString struct{}

func (s *cbString) ReadASN1Int64() (int64, bool)        { return 0, true }
func (s *cbString) ReadInt32() (int32, bool)            { return 0, true }
func (s *cbString) ReadASN1Length() (uint32, bool)      { return 0, true }

// BUG: parsed length drives a classic three-part `for i := 0; i < length; i++`
// without an upper-bound cap. Attacker-controlled length values close to
// math.MaxInt64 will pin the goroutine. No `length > maxLen` guard.
func ParseTLVUnbounded(s *cbString) []byte {
	length, _ := s.ReadASN1Int64()
	out := []byte{}
	for i := int64(0); i < length; i++ {
		out = append(out, byte(i))
	}
	return out
}

// BUG: parsed length drives a countdown loop `for length > 0` without
// any cap. Same shape — attacker decides how many iterations.
func ConsumeBytesUnbounded(in string) string {
	length, _ := strconv.ParseUint(in, 10, 32)
	acc := ""
	for length > 0 {
		acc += "."
		length -= 1
	}
	return acc
}

// BUG: parsed length cast to int drives the loop bound.
func ReadFieldsUnbounded(buf []byte) [][]byte {
	count := binary.BigEndian.Uint32(buf)
	out := make([][]byte, 0)
	for i := uint32(0); i < count; i++ {
		out = append(out, []byte{})
	}
	return out
}
