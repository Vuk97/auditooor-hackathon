package keeper

import (
	"cosmossdk.io/collections"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Ledger is a cosmos `collections` handle. Its .Push write is NOT covered by
// any existing arm sink regex (KVStore/keeper-setter) -> exercises the census
// collections gap-closure. The value written derives from map-iteration ORDER
// (range over an unsorted map) -> map_range_order provenance (G1 oracle).
type Keeper struct {
	Ledger collections.Sequence
}

func (k Keeper) DistributeAll(ctx sdk.Context) {
	pending := map[string]uint64{}
	pending["x"] = 5
	pending["y"] = 7
	for addr, amt := range pending {
		_ = addr
		k.Ledger.Push(amt)
	}
}
