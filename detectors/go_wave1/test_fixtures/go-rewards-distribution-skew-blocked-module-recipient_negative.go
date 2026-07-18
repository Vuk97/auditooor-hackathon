// fixture: negative, reward routing validates recipients and aligns rounding.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type Dec interface {
	Quo(Dec) (Dec, error)
	Add(Dec) (Dec, error)
	TruncateInt() sdk.Int
}

// Dynamic module routing is constrained by an allowlist before funds move.
func (k Keeper) RouteDelegatorReward(ctx sdk.Context, targetModule string, reward sdk.Coins) error {
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

// The rounded reward amount is used to derive the share that is recorded, so
// funded coins and entitlement accounting stay aligned.
func (k Keeper) AllocateDelegatorReward(ctx sdk.Context, topicID uint64, reputer sdk.AccAddress, delegatorReward Dec, totalStake Dec) error {
	truncatedReward := delegatorReward.TruncateInt()
	rewardCoins := sdk.NewCoins(sdk.NewCoin("stake", truncatedReward))
	shareFromCoins, err := k.NewDecFromSdkInt(truncatedReward)
	if err != nil {
		return err
	}
	addShare, err := shareFromCoins.Quo(totalStake)
	if err != nil {
		return err
	}
	currentShare, err := k.GetDelegateRewardPerShare(ctx, topicID, reputer)
	if err != nil {
		return err
	}
	newShare, err := currentShare.Add(addShare)
	if err != nil {
		return err
	}
	if err := k.SetDelegateRewardPerShare(ctx, topicID, reputer, newShare); err != nil {
		return err
	}
	return k.bankKeeper.SendCoinsFromModuleToModule(
		ctx,
		types.RewardsModuleName,
		types.PendingRewardForDelegatorAccountName,
		rewardCoins,
	)
}

// Account-recipient reward payout rejects blocked and module-account targets.
func (k Keeper) PayoutReward(ctx sdk.Context, recipient sdk.AccAddress, reward sdk.Coins) error {
	if k.bankKeeper.BlockedAddr(recipient) {
		return ErrBlockedAddress
	}
	if k.accountKeeper.GetModuleAccount(ctx, recipient.String()) != nil {
		return ErrModuleAccountRecipient
	}
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.RewardsModuleName, recipient, reward)
}
