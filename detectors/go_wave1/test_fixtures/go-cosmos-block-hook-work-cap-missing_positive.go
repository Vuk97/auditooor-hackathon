// fixture: positive - block hook drains unbounded attacker-growable work.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k Keeper) EndBlocker(ctx sdk.Context) {
	for _, order := range k.GetAllOrders(ctx) {
		k.matchOrder(ctx, order)
	}
}

func (k Keeper) BeginBlocker(ctx sdk.Context) {
	store := ctx.KVStore(k.storeKey)
	it := store.Iterator(nil, nil)
	defer it.Close()
	for ; it.Valid(); it.Next() {
		k.applyQueuedSettlement(ctx, it.Value())
	}
}
