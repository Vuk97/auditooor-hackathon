// Pattern 20 — NEGATIVE fixture.
//
// CleanupSigningKeyshareSecretPostFix uses a `committed` boolean to gate
// the deferred Rollback. After Commit succeeds, the deferred Rollback is
// skipped via the `if !committed` guard. The detector must NOT fire.
//
// Mirrors the post-fix shape introduced in SP-6390.
package fixturen

import (
	"context"

	"github.com/spark/entephemeral"
)

// CleanupSigningKeyshareSecretPostFix — the defended shape.
func CleanupSigningKeyshareSecretPostFix(ctx context.Context, ephemeralDB *entephemeral.Client) error {
	ephemeralTx, err := ephemeralDB.Tx(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = ephemeralTx.Rollback()
		}
	}()

	if err := doDeleteN(ctx, ephemeralTx); err != nil {
		return err
	}

	if err := ephemeralTx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func doDeleteN(ctx context.Context, tx *entephemeral.Tx) error { return nil }
