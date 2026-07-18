// Negative fixture 1: NewHint followed by enforceWidthConditional — no finding.
package mycirc

import (
	"github.com/Consensys/gnark/frontend"
	"github.com/Consensys/gnark/std/math/emulated"
)

type SafeCircuit struct {
	A emulated.Element[emulated.BN254Fp]
}

func (c *SafeCircuit) Define(api frontend.API) error {
	field, _ := emulated.NewField[emulated.BN254Fp](api)

	result, _ := field.NewHint(myHintFn, 1, c.A.Limbs...)
	// Properly enforce limb widths before use.
	field.EnforceWidthConditional(result[0])
	_ = field.Reduce(result[0])
	return nil
}
