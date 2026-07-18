// Pattern 32 — POSITIVE fixture for
//   go.crypto.panic.zero_or_negative_length_reaches_make_slice
//
// Mirrors Swival #047/#048/#049/#052/#053. Caller-supplied integer
// length flows directly into make([]byte, n) with no zero/negative
// guard. Negative n panics; zero n silently allocates an empty slice
// causing logic divergence downstream.
package fixture

// BUG: caller-controlled n reaches make without a guard.
func AllocBuffer(n int) []byte {
	return make([]byte, n)
}

// BUG: same shape with the (size, cap) make form.
func AllocPaddedBuffer(n int) []byte {
	return make([]byte, 0, n)
}

// BUG: int32 parameter still vulnerable to the same shape.
func AllocLength(n int32) []byte {
	buf := make([]byte, n)
	_ = buf
	return buf
}
