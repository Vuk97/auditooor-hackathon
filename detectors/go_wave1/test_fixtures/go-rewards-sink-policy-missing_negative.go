// fixture: negative, rewards sinks are policy checked before funds move.
package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

func (k Keeper) RouteRewards(ctx sdk.Context, targetModule string, reward sdk.Coins) error {
	if !k.AllowedRewardModule(ctx, targetModule) {
		return ErrUnexpectedRewardModule
	}
	return k.bankKeeper.SendCoinsFromModuleToModule(
		ctx,
		types.RewardsModuleName,
		targetModule,
		reward,
	)
}

func (k Keeper) PayDelegatorReward(ctx sdk.Context, recipient sdk.AccAddress, reward sdk.Coins) error {
	if k.bankKeeper.BlockedAddr(recipient) {
		return ErrBlockedAddress
	}
	if k.accountKeeper.GetModuleAccount(ctx, recipient.String()) != nil {
		return ErrModuleAccountRecipient
	}
	return k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx,
		types.RewardsModuleName,
		recipient,
		reward,
	)
}
