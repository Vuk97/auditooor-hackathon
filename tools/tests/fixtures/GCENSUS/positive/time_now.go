package keeper

import (
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// The consensus write k.SetDeadline derives from wall-clock time.Now() -> two
// honest validators compute different deadlines -> AppHash divergence.
// wall_clock provenance (G4 oracle reused).
func (k Keeper) OnTick(ctx sdk.Context) {
	deadline := time.Now().Unix()
	k.SetDeadline(ctx, deadline)
}
