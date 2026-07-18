// fixture: positive — map iteration with consensus side effects, no sort.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ranges a Go map and writes store -> AppHash divergence.
func (k Keeper) DistributeRewards(ctx sdk.Context) {
	rewardMap := make(map[string]sdk.Coin)
	rewardMap = k.collectRewards(ctx)
	for addr, coin := range rewardMap {
		k.bankKeeper.SendCoins(ctx, k.pool, addr, coin)
	}
}

// ranges a balances map and emits events in iteration order.
func (k Keeper) EmitBalances(ctx sdk.Context) {
	balancesByID := k.allBalances(ctx)
	for id, bal := range balancesByID {
		ctx.EventManager().EmitEvent(balEvent(id, bal))
	}
}

// ranges a map and appends to an ordered slice consumed by consensus.
func (k Keeper) OrderedMarkets(ctx sdk.Context) []Market {
	out := []Market{}
	marketSet := k.marketMap(ctx)
	for _, m := range marketSet {
		out = append(out, m)
	}
	return out
}
