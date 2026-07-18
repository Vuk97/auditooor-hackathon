// fixture: negative — every fund-moving SDK error is bound and checked.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// error checked inline.
func (k Keeper) Payout(ctx sdk.Context, to sdk.AccAddress, amt sdk.Coins) error {
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "pool", to, amt); err != nil {
		return err
	}
	ctx.EventManager().EmitEvent(payoutEvent(to, amt))
	return nil
}

// error captured then checked.
func (k Keeper) Inflate(ctx sdk.Context, amt sdk.Coins) error {
	err := k.bankKeeper.MintCoins(ctx, "mint", amt)
	if err != nil {
		return err
	}
	return nil
}

// error returned directly.
func (k Keeper) Rebalance(ctx sdk.Context, from, to sdk.AccAddress) error {
	return k.bankKeeper.SendCoins(ctx, from, to, k.dust(from))
}
