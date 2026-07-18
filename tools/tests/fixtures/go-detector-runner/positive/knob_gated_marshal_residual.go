// Pattern 18 — POSITIVE fixture for
//   go.spark.leaf_marshal.knob_gated_residual_disclosure
//
// QueryPendingTransfersResidual marshals a transfer via the unfiltered
// MarshalProto(ctx) under a knob-gated branch. There is NO
// MarshalProtoForReceiver companion call. When the
// isMimoReceiveEnabled knob is OFF (the default before rollout) the
// receiver gets the unfiltered MarshalProto and observes sibling
// receivers' leaves.
//
// Mirrors SP-5846 (``25c37ff813``) on buildonspark/spark.
package fixture

import (
	"context"

	"github.com/spark/knobs"
)

type Transfer struct{}

func (t *Transfer) MarshalProto(ctx context.Context) (*Transfer, error) {
	return nil, nil
}

type Handler struct{}

// QueryPendingTransfersResidual — the residual shape.
func (h *Handler) QueryPendingTransfersResidual(ctx context.Context, transfer *Transfer) (*Transfer, error) {
	// Knob-gated branch.
	knobsService := knobs.GetKnobsService(ctx)
	if knobsService.IsMimoReceiveEnabled(ctx) {
		// no per-receiver branch implemented in residual shape: fall
		// through and use unfiltered MarshalProto.
	}
	transferProto, err := transfer.MarshalProto(ctx)
	if err != nil {
		return nil, err
	}
	return transferProto, nil
}
