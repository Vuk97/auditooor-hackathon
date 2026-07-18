// fixture: negative - block hook caps attacker-growable work.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k Keeper) EndBlocker(ctx sdk.Context) {
	const batchSize = 64
	cursor := k.GetOrderCursor(ctx)
	orders := k.GetOrdersPage(ctx, cursor, batchSize)
	for _, order := range orders {
		k.matchOrder(ctx, order)
	}
	k.SetOrderCursor(ctx, cursor+uint64(len(orders)))
}

func (k Keeper) BeginBlocker(ctx sdk.Context) {
	const batchSize = 64
	store := ctx.KVStore(k.storeKey)
	it := store.Iterator(nil, nil)
	defer it.Close()
	processed := 0
	for ; it.Valid(); it.Next() {
		if processed >= batchSize {
			break
		}
		k.applyQueuedSettlement(ctx, it.Value())
		processed++
	}
}
