// fixture: positive — fund-moving SDK errors discarded or ignored.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// error explicitly discarded with _.
func (k Keeper) Payout(ctx sdk.Context, to sdk.AccAddress, amt sdk.Coins) error {
	_ = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "pool", to, amt)
	ctx.EventManager().EmitEvent(payoutEvent(to, amt))
	return nil
}

// bare-statement mint call, no error capture at all.
func (k Keeper) Inflate(ctx sdk.Context, amt sdk.Coins) {
	k.bankKeeper.MintCoins(ctx, "mint", amt)
}

// multi-discard form.
func (k Keeper) Rebalance(ctx sdk.Context, from, to sdk.AccAddress) {
	_ = k.bankKeeper.SendCoins(ctx, from, to, k.dust(from))
}
