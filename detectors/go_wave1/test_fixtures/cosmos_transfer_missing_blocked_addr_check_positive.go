// fixture: positive — credit paths skip the blocked-address check.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// distributes rewards with no blocked-addr check.
func (k Keeper) DistributeReward(ctx sdk.Context, recipient sdk.AccAddress, amt sdk.Coins) error {
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "rewards", recipient, amt)
}

// airdrop credit path, named credit action, no freeze check.
func (k Keeper) Airdrop(ctx sdk.Context, to sdk.AccAddress, amt sdk.Coins) error {
	return k.bankKeeper.AddCoins(ctx, to, amt)
}
