// fixture: positive - block hooks iterate unbounded collections, no cap.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// EndBlocker scans the whole store prefix every block, no limit.
func (k Keeper) EndBlocker(ctx sdk.Context) {
	store := ctx.KVStore(k.storeKey)
	it := store.Iterator(nil, nil)
	defer it.Close()
	for ; it.Valid(); it.Next() {
		k.processOrder(ctx, it.Value())
	}
}

// BeginBlocker ranges every market with no batch cap.
func (k Keeper) BeginBlocker(ctx sdk.Context) {
	for _, m := range k.GetAllMarkets(ctx) {
		k.recalcFunding(ctx, m)
	}
}

// PreBlocker drains every queued settlement through an unbounded helper.
func (k Keeper) PreBlocker(ctx sdk.Context) {
	k.IterateAllSettlements(ctx, func(s Settlement) bool {
		k.applySettlement(ctx, s)
		return false
	})
}
