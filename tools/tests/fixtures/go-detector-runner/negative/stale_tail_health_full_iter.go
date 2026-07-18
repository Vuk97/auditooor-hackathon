// Negative fixture for go.cosmos.stale_tail_health_check (Pattern 45).
// Functions here do iterate the full collection -- pattern must NOT fire.
package keeper

import (
	"context"

	"github.com/stretchr/testify/require"
)

// CheckAllCommitHeights iterates ALL heights and asserts each is non-zero.
// This is the correct full-coverage check -- NOT a stale-tail bug.
func CheckAllCommitHeights(ctx context.Context, t require.TestingT) {
	allHeights := GetAll(ctx)
	for _, h := range allHeights {
		require.NotZero(t, h, "commit height must not be zero")
	}
	// Also reads the tail for quick final sanity.
	latestHeight := GetLatestHeight(ctx)
	require.NotZero(t, latestHeight)
}

// WalkAllCommitInfo uses the full-iteration helper -- safe.
func WalkAllCommitInfo(ctx context.Context) {
	IterateAll(ctx, func(info CommitInfo) bool {
		if info == nil {
			panic("nil commit info encountered")
		}
		return false
	})
}

// NoAssertionTailRead reads the tail but makes no health assertion at all.
// Must NOT fire because there is no health assertion.
func NoAssertionTailRead(ctx context.Context) CommitInfo {
	return GetLast(ctx)
}
