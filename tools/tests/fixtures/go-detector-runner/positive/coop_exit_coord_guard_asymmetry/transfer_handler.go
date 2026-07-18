// Pattern 13 — POSITIVE fixture (sibling file in the same package).
//
// Provides the package-local coop-exit confirmation guard helper
// checkCoopExitTxBroadcasted AND a sibling caller that DOES use it
// (FinalizeTransferWithTransferPackage). This proves the package is
// coop-exit-aware, satisfying the detector's "guard_present" precondition
// without implicating this file in any hits.
package coopexitfixture

import "errors"

type FinalizeTransferWithTransferPackageRequest struct {
	TransferID string
}

type TransferHandler struct{}

// checkCoopExitTxBroadcasted is the package-local coop-exit confirmation
// guard. Receiver-side handlers call it; the coordinator-side
// VerifyAndUpdateTransfer in finalize_signature_handler.go does not.
func checkCoopExitTxBroadcasted(transfer *Transfer) error {
	if transfer == nil {
		return errors.New("transfer nil")
	}
	// In production: check on-chain confirmation height meets
	// KnobWatchChainCoopExitKeyTweakRequiredConfirmations. Stub here.
	return nil
}

// CORRECT GUARDED PATH — receiver-side finalize. NOT a hit: this calls
// the guard so it should be suppressed.
func (h *TransferHandler) FinalizeTransferWithTransferPackage(req *FinalizeTransferWithTransferPackageRequest) error {
	transfer, err := loadTransferForRequest(req.TransferID)
	if err != nil {
		return err
	}
	if err := checkCoopExitTxBroadcasted(transfer); err != nil {
		return err
	}
	transfer.Status = TransferStatusCompleted
	return nil
}
