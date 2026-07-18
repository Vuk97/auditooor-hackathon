// Negative fixture 1: ToNAF with adjacent-pair constraint — no finding.
package ec

import (
	"github.com/Consensys/gnark/frontend"
	"github.com/Consensys/gnark/std/math/bits"
)

func safeScalarDecompose(api frontend.API, scalar frontend.Variable) []frontend.Variable {
	naf := bits.ToNAF(api, scalar)
	// Enforce the no-adjacent-nonzero property.
	for i := 0; i < len(naf)-1; i++ {
		api.AssertIsEqual(api.Mul(naf[i], naf[i+1]), 0)
	}
	return naf
}
