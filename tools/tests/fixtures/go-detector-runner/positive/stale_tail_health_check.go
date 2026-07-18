// Positive fixture for go.cosmos.stale_tail_health_check (Pattern 45).
// Functions below read only the last/tail item from a sequence and apply a
// health assertion, but never iterate the full collection -- stale-tail bug.
package keeper

import (
	"context"

	"github.com/stretchr/testify/require"
)

// CheckLatestCommitHealthTailOnly reads only the last committed height and
// panics if it is zero, but never validates intermediate entries.
func CheckLatestCommitHealthTailOnly(ctx context.Context) {
	latestHeight := GetLatestHeight(ctx)
	if latestHeight == 0 {
		panic("latest committed height is zero -- invariant violated")
	}
	// No range loop over all heights; only the tail is checked.
}

// ValidateLastBlockInfo reads the tail item and applies a require assertion.
func ValidateLastBlockInfo(ctx context.Context, t require.TestingT) {
	info := GetLast(ctx)
	require.NotNil(t, info, "last block info must not be nil")
	// Missing: for _, h := range allHeights { require.NotNil(t, h) }
}

// MustGetLatestCommitInfoHealthy panics on bad tail, ignores earlier entries.
func MustGetLatestCommitInfoHealthy(ctx context.Context) CommitInfo {
	info := MustGetLatest(ctx)
	if info == nil {
		panic("latest commit info is nil")
	}
	return info
}
