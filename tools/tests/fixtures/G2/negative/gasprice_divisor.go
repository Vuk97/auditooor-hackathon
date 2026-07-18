package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

type FeeReq struct {
	GasPrice sdk.Dec
}

type Keeper struct{}

// FeePerGas divides by req.GasPrice. Even though req.* is taint-shaped, the
// divisor is gas-price-shaped, which is Pattern 11's turf. G2 must NOT emit
// it (dedup boundary). => G2 must NOT fire.
func (k Keeper) FeePerGas(ctx sdk.Context, req FeeReq, total sdk.Dec) sdk.Dec {
	return total.Quo(req.GasPrice)
}
