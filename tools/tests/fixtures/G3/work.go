package keeper

// handleTimeouts is a 1-hop hook callee. It contains a nil-map write panic
// source (seen is never make()-init'd) with NO recover() on the path -> POSITIVE.
func (k Keeper) handleTimeouts(ctx Context) error {
	var seen map[uint64]bool
	for _, id := range k.due(ctx) {
		seen[id] = true
		_ = k.unsafeAssert(ctx)
	}
	return nil
}

// unsafeAssert is a 2-hop callee (handleTimeouts -> unsafeAssert is 1 more hop;
// reached at hops>=2). Single-return type assert with no comma-ok -> POSITIVE.
func (k Keeper) unsafeAssert(x any) *Vault {
	return x.(*Vault)
}

// processJobs is a 1-hop callee that is FULLY GUARDED: comma-ok assert,
// zero-checked division, recover on the path -> NEGATIVE (no hypothesis).
func (k Keeper) processJobs(ctx Context, batch int) error {
	defer func() {
		if r := recover(); r != nil {
			_ = r
		}
	}()
	v, ok := any(ctx).(*Vault)
	if !ok {
		return nil
	}
	if batch == 0 {
		return nil
	}
	_ = v.Total / batch
	return nil
}
