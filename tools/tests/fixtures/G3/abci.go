package keeper

// BeginBlocker is a gas-unmetered consensus hook whose panic is not recovered
// by the SDK -> any panic-source on a hook-reachable path halts the chain.
func (k *Keeper) BeginBlocker(ctx Context) error {
	return k.handleTimeouts(ctx)
}

func (k *Keeper) EndBlocker(ctx Context) error {
	return k.processJobs(ctx, MaxBatch)
}
