// fixture: negative — deterministic iteration: keys sorted before the loop.
package keeper

import (
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// keys collected and sorted before the consensus loop.
func (k Keeper) DistributeRewards(ctx sdk.Context) {
	rewardMap := make(map[string]sdk.Coin)
	rewardMap = k.collectRewards(ctx)
	keys := make([]string, 0, len(rewardMap))
	for addr := range rewardMap {
		keys = append(keys, addr)
	}
	sort.Strings(keys)
	for _, addr := range keys {
		k.bankKeeper.SendCoins(ctx, k.pool, addr, rewardMap[addr])
	}
}

// uses a key-ordered store iterator, not a Go map.
func (k Keeper) EmitBalances(ctx sdk.Context) {
	store := ctx.KVStore(k.storeKey)
	it := store.Iterator(nil, nil)
	defer it.Close()
	for ; it.Valid(); it.Next() {
		ctx.EventManager().EmitEvent(balEventRaw(it.Key(), it.Value()))
	}
}

// ranges a slice (not a map) — deterministic by construction.
func (k Keeper) SumOrders(orders []Order) sdk.Int {
	total := sdk.ZeroInt()
	for _, o := range orders {
		total = total.Add(o.Size)
	}
	return total
}
