// Pattern 22 — POSITIVE fixture for
//   go.spark.coordinator_fanout.tx_commit_before_remote_call
//
// SettlePreimageSwapCoordinator (mirrors SP-5783 ``b154174cee``)
// performs a tx-bound update to the transfer row and then fans out to
// remote SOs via ExecuteTaskWithAllOperators WITHOUT committing the
// coordinator's tx between the write and the fanout. Partial fanout
// failure leaves coordinator/remote state divergent.
//
// Two sister functions in the same file ensure the detector flags both.
package fixture

import (
	"context"
)

type Helper struct{}

type Tx struct{}

type TransferRow struct {
	ID     string
	Status string
}

type TransferUpdate struct{}

func (t *TransferRow) Update() *TransferUpdate                    { return &TransferUpdate{} }
func (t *TransferUpdate) SetStatus(s string) *TransferUpdate      { return t }
func (t *TransferUpdate) Save(ctx context.Context) error          { return nil }
func (h *Helper) ExecuteTaskWithAllOperators(ctx context.Context) error { return nil }
func (h *Helper) BroadcastSettleToOperators(ctx context.Context) error  { return nil }

// SettlePreimageSwapCoordinator — coordinator-side write then fanout
// to remote SOs without an intermediate commit.
func SettlePreimageSwapCoordinator(ctx context.Context, helper *Helper, transfer *TransferRow) error {
	intent := "PreimageSwap Coordinator"
	_ = intent
	if err := transfer.Update().SetStatus("SettleCommitted").Save(ctx); err != nil {
		return err
	}
	// Fanout WITHOUT committing — bug shape.
	if err := helper.ExecuteTaskWithAllOperators(ctx); err != nil {
		return err
	}
	return nil
}

// CoopExitCoordinatorSettleAndFanout — sister function with same shape.
// Mentions "CoopExit" coordinator intent token.
func CoopExitCoordinatorSettleAndFanout(ctx context.Context, helper *Helper, transfer *TransferRow) error {
	// "CoopExit" coordinator-intent token in the body.
	_ = "CoopExit"
	if err := transfer.Update().SetStatus("CoopExitCommitted").Save(ctx); err != nil {
		return err
	}
	if err := helper.BroadcastSettleToOperators(ctx); err != nil {
		return err
	}
	return nil
}
