package keeper

import (
	"math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// getBlockDelay computes a float-derived block delay and RETURNS it (the
// caller decides what to do). No consensus store-write in this body, so the
// nondeterministic-source-into-state predicate must NOT fire. This is the
// mutation-kill witness: dropping the store-write gate would make it fire.
func (k Keeper) getBlockDelay(ctx sdk.Context, delayPeriod uint64) uint64 {
	expected := k.GetMaxExpectedTimePerBlock(ctx)
	if expected == 0 {
		return 0
	}
	return uint64(math.Ceil(float64(delayPeriod) / float64(expected)))
}
