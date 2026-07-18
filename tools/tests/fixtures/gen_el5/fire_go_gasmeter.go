package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

// Cosmos keeper gates on a hard-coded remaining-gas threshold.
func (k Keeper) Step(ctx sdk.Context) error {
	if ctx.GasMeter().GasConsumed() > 500000 {   // <-- go gasleft-threshold
		return ErrOutOfGas
	}
	return nil
}
