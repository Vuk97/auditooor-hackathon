// Pattern 14 — POSITIVE fixture for
//   go.spark.coop_exit.key_tweak_resumability
//
// Pre-SP-2988 vulnerable shape: tweakKeysForCoopExitVulnerable iterates the
// coop-exit transfer leaves AND mutates per-leaf state via ClearKeyTweak()
// + Update().Save(ctx) but DOES NOT have an in-loop idempotency guard. A
// coordinator restart partway through the loop will re-process leaves that
// were already cleared in the prior run, diverging ephemeral / main commit
// state.
//
// No RegisterResumeHandler / OnStartup registration in the file either, so
// the file-level resume-handler suppression does not fire.
package fixturep14

import (
	"context"
	"fmt"
)

type leafRow struct {
	KeyTweak []byte
	Status   string
}

type entUpdate struct{}

func (e *entUpdate) ClearKeyTweak() *entUpdate { return e }
func (e *entUpdate) SetStatus(s string) *entUpdate { return e }
func (e *entUpdate) Save(ctx context.Context) (*leafRow, error) { return nil, nil }

func (l *leafRow) Update() *entUpdate { return &entUpdate{} }

type transferRow struct{}

func (t *transferRow) QueryTransferLeaves() *transferQuery { return &transferQuery{} }

type transferQuery struct{}

func (q *transferQuery) All(ctx context.Context) ([]*leafRow, error) {
	return nil, nil
}

// Vulnerable: no in-loop continue guarding against an already-cleared
// KeyTweak field. CoopExit + KeyTweak domain tokens both present so the
// detector's domain filter fires.
func tweakKeysForCoopExitVulnerable(ctx context.Context, transfer *transferRow) error {
	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return fmt.Errorf("failed to query transfer leaves for CoopExit: %w", err)
	}
	for _, leaf := range transferLeaves {
		// MISSING resumability guard:
		//   if leaf.KeyTweak == nil { continue }
		//   if len(leaf.KeyTweak) == 0 { continue }
		_ = leaf.KeyTweak
		_, err := leaf.Update().ClearKeyTweak().Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to clear KeyTweak: %w", err)
		}
	}
	return nil
}
