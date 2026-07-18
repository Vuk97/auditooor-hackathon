package probe

import (
	"context"
	"time"
)

// A genuine wall-clock-derived consensus write. Under a consensus (keeper / x/)
// path it FIRES; under an off-consensus statesync / light-client path the
// census skips it (precision fix c) because that subsystem is not the
// deterministic app state machine (its time.Now taints no committed value).
func (k Keeper) Persist(ctx context.Context, header *Header) {
	ts := time.Now().Unix()
	header.AppHash = k.hashWith(ts)
}
