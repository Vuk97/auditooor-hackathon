// Pattern 34 — NEGATIVE fixture: every ScalarMult / ScalarBaseMult
// call is guarded by an explicit IsOnCurve / IsIdentity / IsInfinity
// check or a curve.Params().N order check. Detector must NOT fire.
package fixture

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// SAFE: explicit IsOnCurve guard before ScalarMult.
func ScalarMultGuarded(curve elliptic.Curve, x, y *big.Int, k []byte) (*big.Int, *big.Int, error) {
	if !curve.IsOnCurve(x, y) {
		return nil, nil, errors.New("input point is not on curve")
	}
	rx, ry := curve.ScalarMult(x, y, k)
	return rx, ry, nil
}

// SAFE: order check on the scalar via curve.Params().N reference.
func ScalarBaseMultGuarded(curve elliptic.Curve, k []byte) (*big.Int, *big.Int, error) {
	scalar := new(big.Int).SetBytes(k)
	if scalar.Cmp(curve.Params().N) >= 0 {
		return nil, nil, errors.New("scalar exceeds curve order")
	}
	rx, ry := curve.ScalarBaseMult(k)
	return rx, ry, nil
}

// SAFE: IsIdentity precondition on a custom curve type.
type customCurve struct{}

func (c *customCurve) ScalarMultBase(k []byte) ([]byte, []byte) { return k, k }
func (c *customCurve) IsIdentity() bool                          { return false }

func DerivePointGuarded(c *customCurve, k []byte) ([]byte, []byte, error) {
	if c.IsIdentity() {
		return nil, nil, errors.New("identity point")
	}
	return c.ScalarMultBase(k)
}
