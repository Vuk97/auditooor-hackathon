// Positive fixture 2: Element struct literal with Limbs field, no width enforcement.
package mycirc

import (
	"github.com/Consensys/gnark/frontend"
	"github.com/Consensys/gnark/std/math/emulated"
)

type UncheckedCircuit struct {
	X frontend.Variable
}

func buildElement(api frontend.API, limbs []frontend.Variable) emulated.Element[emulated.Secp256k1Fp] {
	// Direct Element struct literal with Limbs — no enforceWidthConditional.
	return emulated.Element[emulated.Secp256k1Fp]{
		Limbs: limbs,
	}
}
