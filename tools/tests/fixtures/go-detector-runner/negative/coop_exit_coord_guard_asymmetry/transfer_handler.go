// Pattern 13 — NEGATIVE fixture sibling file.
//
// Provides the package-local guard helper checkCoopExitTxBroadcasted
// (so the package is coop-exit-aware) and a sibling caller that uses
// it. Detector must NOT fire here.
package coopexitfixturen

import "errors"

type FinalizeTransferWithTransferPackageRequest struct {
	TransferID string
}

type TransferHandler struct{}

func checkCoopExitTxBroadcasted(transfer *Transfer) error {
	if transfer == nil {
		return errors.New("transfer nil")
	}
	return nil
}

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
