// Pattern 22 — NEGATIVE fixture.
//
// CoopExitCoordinatorWithCommit performs the tx-bound write, COMMITS the
// coordinator tx, and only THEN fans out to remote SOs. Detector must
// NOT fire.
//
// Mirrors the post-fix shape introduced in SP-5783.
package fixturen

import (
	"context"
)

type HelperN struct{}

type TxN struct{}

type TransferRowN struct {
	ID     string
	Status string
}

type TransferUpdateN struct{}

func (t *TransferRowN) Update() *TransferUpdateN                    { return &TransferUpdateN{} }
func (t *TransferUpdateN) SetStatus(s string) *TransferUpdateN      { return t }
func (t *TransferUpdateN) Save(ctx context.Context) error           { return nil }
func (h *HelperN) ExecuteTaskWithAllOperators(ctx context.Context) error { return nil }
func (n *TxN) Commit() error                                        { return nil }

// CoopExitCoordinatorWithCommit — defended: commit BEFORE fanout.
func CoopExitCoordinatorWithCommit(ctx context.Context, helper *HelperN, transfer *TransferRowN, tx *TxN) error {
	_ = "CoopExit Coordinator"
	if err := transfer.Update().SetStatus("CoopExitCommitted").Save(ctx); err != nil {
		return err
	}
	// Commit BEFORE fanout — bug shape suppressed.
	if err := tx.Commit(); err != nil {
		return err
	}
	return helper.ExecuteTaskWithAllOperators(ctx)
}
