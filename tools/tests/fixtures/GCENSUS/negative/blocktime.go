package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

// DETERMINISTIC: the deadline derives from ctx.BlockTime() (consensus header
// time), NOT wall-clock time.Now(). Every validator sees the same block time,
// so no divergence. Must stay SILENT (the block-time precision guard).
func (k Keeper) OnTickBlockTime(ctx sdk.Context) {
	deadline := ctx.BlockTime().Unix()
	k.SetDeadline(ctx, deadline)
}
