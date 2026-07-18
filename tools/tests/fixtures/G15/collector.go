package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// collectDueVuln mirrors the PoC-confirmed nuva payout.go shape: a WalkDue
// callback whose per-block cap `if processed == batchSize { return true }` is
// BYPASSED by a sibling `if ... { return false, nil }` guard that returns
// BEFORE `processed++`, so skipped items are walked uncounted. FIRES.
func (k *Keeper) collectDueVuln(ctx sdk.Context, batchSize int) error {
	now := ctx.BlockTime().Unix()
	processed := 0
	return k.Queue.WalkDue(ctx, now, func(ts int64, id uint64, addr sdk.AccAddress) (stop bool, err error) {
		v, ok := k.tryGet(ctx, addr)
		if ok && v.Paused {
			return false, nil
		}
		if processed == batchSize {
			return true, nil
		}
		processed++
		k.enqueue(id)
		return false, nil
	})
}

// collectDueClean is the benign sibling: `processed++` runs at the TOP of the
// callback, BEFORE any continue-exit, so every walked item is counted and the
// cap cannot be bypassed. SILENT.
func (k *Keeper) collectDueClean(ctx sdk.Context, batchSize int) error {
	now := ctx.BlockTime().Unix()
	processed := 0
	return k.Queue.WalkDue(ctx, now, func(ts int64, id uint64, addr sdk.AccAddress) (stop bool, err error) {
		processed++
		v, ok := k.tryGet(ctx, addr)
		if ok && v.Paused {
			return false, nil
		}
		if processed == batchSize {
			return true, nil
		}
		k.enqueue(id)
		return false, nil
	})
}

// collectForRangeVuln is the for-range variant: a `continue` guard skips items
// BEFORE `count++`, while a `break` cap `if count >= maxN { break }` gives the
// (bypassable) per-iteration bound. FIRES.
func (k *Keeper) collectForRangeVuln(items []uint64, maxN int) {
	count := 0
	for _, id := range items {
		if k.skip(id) {
			continue
		}
		if count >= maxN {
			break
		}
		count++
		k.enqueue(id)
	}
}

// collectNoBound has a continue-skip but NO per-iteration cap on the counter
// (no `if count == bound { stop }`). That is the uncapped shape owned by
// G11 / Pattern 36, NOT G15. SILENT (disjoint-predicate dedup).
func (k *Keeper) collectNoBound(items []uint64) {
	count := 0
	for _, id := range items {
		if k.skip(id) {
			continue
		}
		count++
		k.enqueue(id)
	}
}
