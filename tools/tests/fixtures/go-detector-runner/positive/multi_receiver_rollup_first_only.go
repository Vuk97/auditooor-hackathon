// Pattern 24 — POSITIVE fixture for
//   go.spark.multi_receiver.rollup_first_only
//
// CancelStuckTransfer (mirrors SP-5842 ``c78104eab8``) collapses to
// ``QueryReceivers().First(ctx)`` and only mutates ``receivers[0]``,
// leaving the remaining receivers in a divergent state. A correct
// implementation must enumerate every receiver via a range loop.
//
// Two sister functions in the same file ensure the detector flags both.
package fixture

import (
	"context"
)

type Helper struct{}

type TransferRow struct {
	ID                string
	transferReceivers []*ReceiverRow
}

type ReceiverRow struct {
	ID     string
	Status string
}

type ReceiverUpdate struct{}

func (r *ReceiverRow) Update() *ReceiverUpdate                  { return &ReceiverUpdate{} }
func (r *ReceiverUpdate) SetStatus(s string) *ReceiverUpdate     { return r }
func (r *ReceiverUpdate) Save(ctx context.Context) error         { return nil }

type ReceiverQuery struct{}

func (t *TransferRow) QueryReceivers() *ReceiverQuery                                  { return &ReceiverQuery{} }
func (q *ReceiverQuery) Where(...interface{}) *ReceiverQuery                            { return q }
func (q *ReceiverQuery) First(ctx context.Context) (*ReceiverRow, error)                { return nil, nil }
func (q *ReceiverQuery) Only(ctx context.Context) (*ReceiverRow, error)                 { return nil, nil }

// CancelStuckTransfer — bug shape: only the first receiver is updated.
func CancelStuckTransfer(ctx context.Context, transfer *TransferRow) error {
	receiver, err := transfer.QueryReceivers().First(ctx)
	if err != nil {
		return err
	}
	if err := receiver.Update().SetStatus("Cancelled").Save(ctx); err != nil {
		return err
	}
	return nil
}

// RefundExpiredTransfer — sister bug-shape: indexes ``receivers[0]`` then
// only mutates that one. References transferReceivers in the body.
func RefundExpiredTransfer(ctx context.Context, transfer *TransferRow) error {
	receivers := transfer.transferReceivers
	if len(receivers) == 0 {
		return nil
	}
	if err := receivers[0].Update().SetStatus("Refunded").Save(ctx); err != nil {
		return err
	}
	return nil
}
