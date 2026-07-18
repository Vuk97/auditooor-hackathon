// Pattern 19 — POSITIVE fixture for
//   go.spark.background_session.parent_tx_reopen_hook_missing
//
// CleanupChainwatcherSecretsResidual obtains an ephemeral tx from the
// parent context and registers a deferred cleanup that uses it. There is
// NO OnCommit / OnRollback / bindTx hook registration; if the parent tx
// commits, the deferred Rollback no-ops and the cleanup state silently
// diverges.
//
// Mirrors SP-6329 (``dfb6b50ec9``) on buildonspark/spark.
package fixture

import (
	"context"

	"github.com/spark/entephemeral"
)

type ChainwatcherSession struct {
	tx *entephemeral.Tx
}

// CleanupChainwatcherSecretsResidual — chainwatcher cleanup uses parent
// tx; never re-binds.
func CleanupChainwatcherSecretsResidual(ctx context.Context, sess *ChainwatcherSession) error {
	parentTx, err := entephemeral.GetTxFromContext(ctx)
	if err != nil {
		return err
	}
	sess.tx = parentTx
	chainwatcherCleanupHook(parentTx)
	defer func() {
		_ = sess.tx.Rollback()
	}()
	if err := orphanedSigningKeyshareSecretCleanup(ctx, sess.tx); err != nil {
		return err
	}
	return nil
}

func chainwatcherCleanupHook(tx *entephemeral.Tx) {}

func orphanedSigningKeyshareSecretCleanup(ctx context.Context, tx *entephemeral.Tx) error {
	return nil
}

func doCleanupWork(ctx context.Context, tx *entephemeral.Tx) error {
	return nil
}
