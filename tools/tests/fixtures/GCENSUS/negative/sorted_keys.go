package keeper

import (
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// DETERMINISTIC: the keys are collected and sorted, then the write iterates the
// SORTED slice, so every validator writes in the same order. Must stay SILENT
// (the _MAP_KEY_ORDER precision guard neutralizes the map-range source).
func (k Keeper) EndBlockSorted(ctx sdk.Context) {
	rewards := map[string]uint64{}
	rewards["a"] = 1
	keys := make([]string, 0, len(rewards))
	for kk := range rewards {
		keys = append(keys, kk)
	}
	sort.Strings(keys)
	for _, addr := range keys {
		store := ctx.KVStore(k.storeKey)
		store.Set([]byte(addr), sdk.Uint64ToBigEndian(rewards[addr]))
	}
}
