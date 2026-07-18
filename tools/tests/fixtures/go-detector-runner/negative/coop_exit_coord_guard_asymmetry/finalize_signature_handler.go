// Pattern 13 — NEGATIVE fixture (post-SP-2961 fix shape).
//
// Same package shape as the positive fixture, but the coordinator-side
// VerifyAndUpdateTransfer NOW calls checkCoopExitTxBroadcasted (mirroring
// the SP-2961 fix). The detector must NOT fire on either function in
// this package.
package coopexitfixturen

import "errors"

type Transfer struct {
	ID     string
	Status string
}

type FinalizeNodeSignaturesRequest struct {
	TransferID string
}

type FinalizeSignatureHandler struct{}

const (
	TransferStatusReceiverRefundSigned = "RECEIVER_REFUND_SIGNED"
	TransferStatusCompleted            = "COMPLETED"
)

func loadTransferForRequest(_ string) (*Transfer, error) {
	return &Transfer{Status: TransferStatusReceiverRefundSigned}, nil
}

// CORRECT GUARDED PATH (post-SP-2961 fix shape). The coordinator-side
// finalize path now calls checkCoopExitTxBroadcasted before returning.
func (o *FinalizeSignatureHandler) VerifyAndUpdateTransfer(req *FinalizeNodeSignaturesRequest) (*Transfer, error) {
	transfer, err := loadTransferForRequest(req.TransferID)
	if err != nil {
		return nil, err
	}
	if transfer.Status != TransferStatusReceiverRefundSigned {
		return nil, errors.New("transfer not in receiver refund signed status")
	}
	if err := checkCoopExitTxBroadcasted(transfer); err != nil {
		return nil, err
	}
	return transfer, nil
}
