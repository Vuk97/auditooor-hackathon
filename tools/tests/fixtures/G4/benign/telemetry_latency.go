package keeper

import (
	"time"

	"github.com/cosmos/cosmos-sdk/telemetry"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// BeginBlock measures its own latency and writes state. The time.Now() is a
// duration probe (defer MeasureSince) and the float32 is a gauge argument -
// neither feeds consensus state, so this must NOT fire (telemetry FP-guard).
func (k Keeper) BeginBlock(ctx sdk.Context) {
	beginBlockerStart := time.Now()
	defer telemetry.ModuleMeasureSince("mymod", beginBlockerStart, "begin_blocker")
	k.SetParams(ctx, k.GetParams(ctx))
	telemetry.SetGaugeWithLabels(
		[]string{"mymod", "height"},
		float32(ctx.BlockHeight()),
		nil,
	)
}
