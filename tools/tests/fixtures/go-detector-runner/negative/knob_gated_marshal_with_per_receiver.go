// Pattern 18 — NEGATIVE fixture.
//
// QueryPendingTransfersFiltered branches BOTH knob-gated paths:
// MarshalProtoForReceiver on the receiver-specific path, MarshalProto on
// the sender / non-MIMO path. The detector must NOT fire because the
// per-receiver companion call is present in the same body.
package fixturen

import (
	"context"

	"github.com/spark/knobs"
)

type TransferN struct{}

func (t *TransferN) MarshalProto(ctx context.Context) (*TransferN, error) {
	return nil, nil
}
func (t *TransferN) MarshalProtoForReceiver(ctx context.Context, walletPubkey []byte) (*TransferN, error) {
	return nil, nil
}

type HandlerN struct{}

// QueryPendingTransfersFiltered — defended shape.
func (h *HandlerN) QueryPendingTransfersFiltered(ctx context.Context, transfer *TransferN, walletPub []byte) (*TransferN, error) {
	useMIMO := knobs.GetKnobsService(ctx).IsMimoReceiveEnabled(ctx)
	var transferProto *TransferN
	var err error
	if useMIMO && walletPub != nil {
		transferProto, err = transfer.MarshalProtoForReceiver(ctx, walletPub)
	} else {
		transferProto, err = transfer.MarshalProto(ctx)
	}
	if err != nil {
		return nil, err
	}
	return transferProto, nil
}
