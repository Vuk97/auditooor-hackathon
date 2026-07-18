// Positive fixture 1: NewHint used to create Element without width enforcement.
package mycirc

import (
	"github.com/Consensys/gnark/frontend"
	"github.com/Consensys/gnark/std/math/emulated"
)

type MyCircuit struct {
	A emulated.Element[emulated.BN254Fp]
	B emulated.Element[emulated.BN254Fp]
}

func (c *MyCircuit) Define(api frontend.API) error {
	field, _ := emulated.NewField[emulated.BN254Fp](api)

	// BUG: NewHint creates an Element whose limbs are not width-constrained.
	// enforceWidthConditional is never called before consuming the element.
	result, _ := field.NewHint(myHintFn, 1, c.A.Limbs...)
	_ = field.Reduce(result[0])  // Reduce consumes result without width check.
	return nil
}
