// Pattern 13 — POSITIVE fixture (package_coop_exit_guard arm).
//
// Models SP-2961 (LEAD 1) coop-exit coordinator confirmation-guard
// asymmetry. The package contains the coop-exit confirmation guard
// helper checkCoopExitTxBroadcasted (defined in transfer_handler.go in
// the same package). One sibling — FinalizeTransferWithTransferPackage —
// calls the guard. The function under inspection here —
// VerifyAndUpdateTransfer — is the coordinator-side finalize path that
// loads a transfer in pre-finalize ReceiverRefundSigned state and
// returns it to the caller for terminal-status mutation, but it does NOT
// call the guard. The detector's package_coop_exit_guard arm should
// flag VerifyAndUpdateTransfer.
package coopexitfixture

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

// THE BUG SHAPE — coordinator-side coop-exit finalize path.
//
// Loads a transfer asserted to be in TransferStatusReceiverRefundSigned
// (a coop-exit-eligible pre-finalize state) and returns it for terminal
// status mutation by the caller, but never calls
// checkCoopExitTxBroadcasted. The receiver-side path
// (FinalizeTransferWithTransferPackage in transfer_handler.go) DOES
// call the guard, producing the LEAD 1 asymmetry.
func (o *FinalizeSignatureHandler) VerifyAndUpdateTransfer(req *FinalizeNodeSignaturesRequest) (*Transfer, error) {
	transfer, err := loadTransferForRequest(req.TransferID)
	if err != nil {
		return nil, err
	}
	if transfer.Status != TransferStatusReceiverRefundSigned {
		return nil, errors.New("transfer not in receiver refund signed status")
	}
	// Missing: if err := checkCoopExitTxBroadcasted(transfer); err != nil { return nil, err }
	return transfer, nil
}
