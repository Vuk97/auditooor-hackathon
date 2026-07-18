package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

// NEGATIVE (precision fix d): every iteration writes a DISTINCT key
// (store.Set(<loopkey>, ...)), so the committed state is INDEPENDENT of map
// iteration order (order-invariant) -> not an app-hash divergence -> SILENT.
func (k Keeper) Reindex(ctx sdk.Context, entries map[string][]byte) {
	store := ctx.KVStore(k.storeKey)
	for id, blob := range entries {
		store.Set([]byte(id), blob)
	}
}
