package keeper

import (
	"context"
	"time"
)

// NEGATIVE (precision fix b): time.Now() reaches ONLY the light-block
// VERIFICATION argument; the returned block (and thus its AppHash) is the
// deterministic chain value. The wall-clock value never flows INTO the written
// AppHash, so the write's value provenance is deterministic -> stay SILENT.
func (k Keeper) StateAt(ctx context.Context, height uint64) State {
	block := k.verify(ctx, height, time.Now())
	var st State
	st.AppHash = block.AppHash
	return st
}
