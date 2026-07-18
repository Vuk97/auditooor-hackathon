// fixture: negative - block hooks cap per-block work.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const maxPerBlock = 100

// EndBlocker breaks after a bounded batch.
func (k Keeper) EndBlocker(ctx sdk.Context) {
	store := ctx.KVStore(k.storeKey)
	it := store.Iterator(nil, nil)
	defer it.Close()
	count := 0
	for ; it.Valid(); it.Next() {
		if count >= maxPerBlock {
			break
		}
		k.processOrder(ctx, it.Value())
		count++
	}
}

// BeginBlocker uses a paginated cursor resumed next block.
func (k Keeper) BeginBlocker(ctx sdk.Context) {
	cursor := k.GetFundingCursor(ctx)
	batch := k.GetMarketsPage(ctx, cursor, maxPerBlock)
	for _, m := range batch {
		k.recalcFunding(ctx, m)
	}
	k.SetFundingCursor(ctx, cursor+uint64(len(batch)))
}

// PreBlocker does fixed O(1) work - must NOT flag.
func (k Keeper) PreBlocker(ctx sdk.Context) {
	k.refreshParams(ctx)
}

// BeginBlocker processes a bounded page from an attacker-growable queue.
func (k Keeper) QueueBeginBlocker(ctx sdk.Context) {
	const batchSize = 50
	cursor := k.GetQueueCursor(ctx)
	page := k.ListQueuedSettlements(ctx, cursor, batchSize)
	for _, s := range page {
		k.applySettlement(ctx, s)
	}
	k.SetQueueCursor(ctx, cursor+uint64(len(page)))
}
