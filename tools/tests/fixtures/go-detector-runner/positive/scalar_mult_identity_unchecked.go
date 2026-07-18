// Pattern 34 — POSITIVE fixture for
//   go.crypto.scalar_mult.identity_point_unchecked
//
// Mirrors Swival #028/#029/#034/#035/#066/#067/#073 — secp / NIST
// curves silently accept malformed (x=0, y=0) or sub-group order
// points. Without IsOnCurve / IsIdentity / IsInfinity guards, the
// scalar / point op either leaks structural invariants or panics.
package fixture

import (
	"crypto/elliptic"
	"math/big"
)

// BUG: ScalarMult invoked on caller-supplied (x, y) with no
// IsOnCurve / IsIdentity guard.
func ScalarMultUnsafe(curve elliptic.Curve, x, y *big.Int, k []byte) (*big.Int, *big.Int) {
	rx, ry := curve.ScalarMult(x, y, k)
	return rx, ry
}

// BUG: ScalarBaseMult used without any sub-group order check on the
// scalar (no `curve.Params().N` reference in the body).
func ScalarBaseMultUnsafe(curve elliptic.Curve, k []byte) (*big.Int, *big.Int) {
	return curve.ScalarBaseMult(k)
}

// BUG: ScalarMultBase variant (different curve impls expose this name)
// — same shape, no IsOnCurve guard.
type customCurve struct{}

func (c *customCurve) ScalarMultBase(k []byte) ([]byte, []byte) { return k, k }

func DerivePointUnsafe(c *customCurve, k []byte) ([]byte, []byte) {
	return c.ScalarMultBase(k)
}
