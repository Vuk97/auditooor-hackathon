// Pattern 20 — POSITIVE fixture for
//   go.spark.post_commit_rollback_unprotected
//
// CleanupSigningKeyshareSecretPreFix registers a deferred Rollback() on
// ephemeralTx and then calls ephemeralTx.Commit(). After Commit succeeds,
// the deferred Rollback fires and triggers OnRollback hooks that mutate
// state Commit already cleared. There is NO `committed` boolean guard.
//
// Mirrors SP-6390 (``a5550e78e5632a8675bfefdad74a6e6054d89d2f``) on
// buildonspark/spark — both `cleanupSigningKeyshareSecret` and
// `prepareSigningKeyshareSecretRotation` had this bug class.
package fixture

import (
	"context"

	"github.com/spark/entephemeral"
)

// CleanupSigningKeyshareSecretPreFix — the buggy shape.
func CleanupSigningKeyshareSecretPreFix(ctx context.Context, ephemeralDB *entephemeral.Client) error {
	ephemeralTx, err := ephemeralDB.Tx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = ephemeralTx.Rollback() }()

	if err := doDelete(ctx, ephemeralTx); err != nil {
		return err
	}

	if err := ephemeralTx.Commit(); err != nil {
		return err
	}
	return nil
}

// PrepareSigningKeyshareSecretRotationPreFix — second occurrence of the
// same shape (the real Spark bug had two sister functions).
func PrepareSigningKeyshareSecretRotationPreFix(ctx context.Context) error {
	ephemeralTx, err := entephemeral.GetTxFromContext(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = ephemeralTx.Rollback() }()

	if err := writeRotation(ctx, ephemeralTx); err != nil {
		return err
	}

	return ephemeralTx.Commit()
}

func doDelete(ctx context.Context, tx *entephemeral.Tx) error    { return nil }
func writeRotation(ctx context.Context, tx *entephemeral.Tx) error { return nil }
