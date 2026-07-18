// Positive fixture 2: ToNAF in a helper function, constraint missing.
package ec

import (
	"github.com/Consensys/gnark/frontend"
	"github.com/Consensys/gnark/std/math/bits"
)

func scalarDecompose(api frontend.API, scalar frontend.Variable) []frontend.Variable {
	// Returns NAF decomposition without enforcing non-adjacent property.
	naf := bits.ToNAF(api, scalar)
	// Missing: for i := range naf[:len(naf)-1] { api.AssertIsEqual(api.Mul(naf[i], naf[i+1]), 0) }
	return naf
}
