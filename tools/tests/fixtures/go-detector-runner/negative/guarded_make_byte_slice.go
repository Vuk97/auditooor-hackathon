// Pattern 32 — NEGATIVE fixture: every make([]byte, n) is preceded by
// a zero/negative-length guard on the same param. Detector must NOT
// fire.
package fixture

import "fmt"

// SAFE: explicit `n <= 0` guard before the make call.
func AllocBufferGuarded(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("n must be > 0")
	}
	return make([]byte, n), nil
}

// SAFE: `n < 0` guard, returning early.
func AllocPaddedGuarded(n int) []byte {
	if n < 0 {
		return nil
	}
	return make([]byte, 0, n)
}

// SAFE: positive-form guard `n > 0` followed by an unconditional path.
func AllocPositive(n int) []byte {
	if n > 0 {
		return make([]byte, n)
	}
	return nil
}

// SAFE: literal length — not a parameter, so the detector should not
// fire even without a guard.
func AllocLiteral() []byte {
	return make([]byte, 32)
}

// SAFE: locally derived length from a freshly-initialised buffer. No
// parameter flow.
func AllocLocal() []byte {
	src := []byte{0x01, 0x02}
	return make([]byte, len(src))
}
