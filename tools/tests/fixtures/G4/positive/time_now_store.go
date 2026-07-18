package keeper

import (
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// EndBlock writes the current wall-clock into consensus state.
// BUG shape: time.Now() is node-local; two validators diverge -> AppHash
// mismatch. HIGH-signal time arm; must FIRE.
func (k Keeper) EndBlock(ctx sdk.Context) {
	now := time.Now()
	k.SetLastTick(ctx, uint64(now.Unix()))
	store := ctx.KVStore(k.storeKey)
	store.Set([]byte("ts"), sdk.Uint64ToBigEndian(uint64(now.Unix())))
}
