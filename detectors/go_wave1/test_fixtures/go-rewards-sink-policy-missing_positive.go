// fixture: positive, rewards flow to unchecked dynamic sinks.
package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

func (k Keeper) RouteRewards(ctx sdk.Context, targetModule string, reward sdk.Coins) error {
	return k.bankKeeper.SendCoinsFromModuleToModule(
		ctx,
		types.RewardsModuleName,
		targetModule,
		reward,
	)
}

func (k Keeper) PayDelegatorReward(ctx sdk.Context, recipient sdk.AccAddress, reward sdk.Coins) error {
	return k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx,
		types.RewardsModuleName,
		recipient,
		reward,
	)
}
