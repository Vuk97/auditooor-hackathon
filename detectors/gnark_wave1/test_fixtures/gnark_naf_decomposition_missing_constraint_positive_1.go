// Positive fixture 1: ToNAF used in scalar mul without adjacent-nonzero constraint.
package scalarMul

import (
	"github.com/Consensys/gnark/frontend"
	"github.com/Consensys/gnark/std/math/bits"
)

type ScalarMulCircuit struct {
	Scalar frontend.Variable
	// ...
}

func (c *ScalarMulCircuit) Define(api frontend.API) error {
	// ToNAF decomposes the scalar; bits in {-1, 0, 1}.
	// BUG: no adjacent-nonzero enforcement follows.
	naf := bits.ToNAF(api, c.Scalar)

	// Downstream scalar multiplication loop assumes canonical NAF.
	// A malicious prover can supply non-canonical NAF with adjacent non-zeros.
	for i := 0; i < len(naf); i++ {
		_ = naf[i] // use naf without constraint
	}
	return nil
}
