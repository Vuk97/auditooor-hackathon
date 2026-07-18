// Pattern 24 — NEGATIVE fixture.
//
// CancelStuckTransfer enumerates every receiver via ``range receivers``
// and updates each one in turn. Detector must NOT fire.
//
// Mirrors the post-fix shape introduced in SP-5842.
package fixturen

import (
	"context"
)

type TransferRowN struct {
	ID                string
	transferReceivers []*ReceiverRowN
}

type ReceiverRowN struct {
	ID     string
	Status string
}

type ReceiverUpdateN struct{}

func (r *ReceiverRowN) Update() *ReceiverUpdateN              { return &ReceiverUpdateN{} }
func (r *ReceiverUpdateN) SetStatus(s string) *ReceiverUpdateN { return r }
func (r *ReceiverUpdateN) Save(ctx context.Context) error      { return nil }

type ReceiverQueryN struct{}

func (t *TransferRowN) QueryReceivers() *ReceiverQueryN                              { return &ReceiverQueryN{} }
func (q *ReceiverQueryN) AllX(ctx context.Context) []*ReceiverRowN                   { return nil }

// CancelStuckTransfer — defended shape: enumerate every receiver.
func CancelStuckTransfer(ctx context.Context, transfer *TransferRowN) error {
	receivers := transfer.transferReceivers
	for _, receiver := range receivers {
		if err := receiver.Update().SetStatus("Cancelled").Save(ctx); err != nil {
			return err
		}
	}
	return nil
}

// RefundExpiredTransfer — defended shape: range over QueryReceivers().AllX(ctx).
func RefundExpiredTransfer(ctx context.Context, transfer *TransferRowN) error {
	for _, receiver := range transfer.QueryReceivers().AllX(ctx) {
		if err := receiver.Update().SetStatus("Refunded").Save(ctx); err != nil {
			return err
		}
	}
	return nil
}
