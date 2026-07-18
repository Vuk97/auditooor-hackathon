// fixture: positive, reward routing can skew module-account balances.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type Dec interface {
	Quo(Dec) (Dec, error)
	Add(Dec) (Dec, error)
	SdkIntTrim() sdk.Int
}

// Dynamic module routing lets callers move reward value into an unexpected
// module account without any allowlist or blocked-recipient policy.
func (k Keeper) RouteDelegatorReward(ctx sdk.Context, targetModule string, reward sdk.Coins) error {
	return k.bankKeeper.SendCoinsFromModuleToModule(
		ctx,
		types.RewardsModuleName,
		targetModule,
		reward,
	)
}

// Full-precision reward shares are recorded, but only a rounded coin amount is
// funded into the pending reward module account.
func (k Keeper) AllocateDelegatorReward(ctx sdk.Context, topicID uint64, reputer sdk.AccAddress, delegatorReward Dec, totalStake Dec) error {
	addShare, err := delegatorReward.Quo(totalStake)
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
		sdk.NewCoins(sdk.NewCoin("stake", delegatorReward.SdkIntTrim())),
	)
}

// Account-recipient reward payout lacks a blocked-address check, so a module
// account or blocked address can be credited through the reward path.
func (k Keeper) PayoutReward(ctx sdk.Context, recipient sdk.AccAddress, reward sdk.Coins) error {
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, types.RewardsModuleName, recipient, reward)
}
