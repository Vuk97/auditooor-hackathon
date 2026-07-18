// Pattern 19 — NEGATIVE fixture.
//
// CleanupChainwatcherSecretsDefended obtains an ephemeral tx from the
// parent context, registers OnCommit / OnRollback reopen-ephemeral hooks
// (via bindTx), and then registers the deferred cleanup. The detector
// must NOT fire because the reopen hooks are wired.
package fixturen

import (
	"context"

	"github.com/spark/entephemeral"
)

type ChainwatcherSessionN struct {
	tx *entephemeral.Tx
}

func (s *ChainwatcherSessionN) bindTx(tx *entephemeral.Tx) {
	tx.OnCommit(func(fn entephemeral.Committer) entephemeral.Committer {
		return fn
	})
	tx.OnRollback(func(fn entephemeral.Rollbacker) entephemeral.Rollbacker {
		return fn
	})
	s.tx = tx
}

// CleanupChainwatcherSecretsDefended — chainwatcher cleanup re-binds via
// OnCommit / OnRollback hooks before deferring rollback.
func CleanupChainwatcherSecretsDefended(ctx context.Context, sess *ChainwatcherSessionN) error {
	parentTx, err := entephemeral.GetTxFromContext(ctx)
	if err != nil {
		return err
	}
	sess.bindTx(parentTx)
	defer func() {
		_ = sess.tx.Rollback()
	}()
	if err := doCleanupWorkN(ctx, sess.tx); err != nil {
		return err
	}
	return nil
}

func doCleanupWorkN(ctx context.Context, tx *entephemeral.Tx) error {
	return nil
}
