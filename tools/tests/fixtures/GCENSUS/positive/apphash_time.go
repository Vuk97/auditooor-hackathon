package keeper

import (
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// POSITIVE (proves precision fixes a+b are NOT vacuous): the committed AppHash
// is DERIVED from wall-clock time.Now() - `ts` traces the source and flows into
// the written value - so two honest validators diverge. wall_clock provenance
// onto a genuine AppHash write-LHS (sink_kind=apphash).
func (k Keeper) Seal(ctx sdk.Context, header *Header) {
	ts := time.Now().Unix()
	header.AppHash = k.hashWith(ts)
}
