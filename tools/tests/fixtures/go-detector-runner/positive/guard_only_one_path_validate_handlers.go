// Pattern 2 — POSITIVE fixture (sharpened arm, package_project_guard).
//
// Models the LEAD H-D mechanism in spark/so/handler:
//   * project-specific guard validateTransferLeavesNotExitedToL1 lives
//     in the package and is called by exactly ONE sibling
//     (CommitSenderKeyTweaks);
//   * 4 OTHER public methods on TransferHandler take a *...Request
//     parameter (gRPC handler shape) and mutate Status without calling
//     the guard.
//
// Sharpened detector arm should flag all 4 unguarded handlers.
package fixtureph

type Transfer struct {
	Status string
}

type TransferHandler struct{}

type ClaimTransferTweakKeysRequest struct{ TransferID string }
type ClaimTransferRequest struct{ TransferID string }
type ClaimTransferSignRefundsRequest struct{ TransferID string }
type InitiateSettleReceiverKeyTweakRequest struct{ TransferID string }

func (h *TransferHandler) loadTransfer(_ string) *Transfer { return &Transfer{} }

// project-specific guard — validate* prefix, takes a *Transfer.
func (h *TransferHandler) validateTransferLeavesNotExitedToL1(t *Transfer, op string) error {
	_ = t
	_ = op
	return nil
}

// THE ONLY caller of the guard.
func (h *TransferHandler) CommitSenderKeyTweaks(req *ClaimTransferRequest) error {
	t := h.loadTransfer(req.TransferID)
	if err := h.validateTransferLeavesNotExitedToL1(t, "commit"); err != nil {
		return err
	}
	t.Status = "SENDER_KEY_TWEAKED"
	return nil
}

// 4 missing-guard sites — all public methods, all take *...Request, all mutate Status.

func (h *TransferHandler) ClaimTransferTweakKeys(req *ClaimTransferTweakKeysRequest) error {
	t := h.loadTransfer(req.TransferID)
	t.Status = "RECEIVER_KEY_TWEAKED"
	return nil
}

func (h *TransferHandler) ClaimTransfer(req *ClaimTransferRequest) error {
	t := h.loadTransfer(req.TransferID)
	t.Status = "COMPLETED"
	return nil
}

func (h *TransferHandler) ClaimTransferSignRefunds(req *ClaimTransferSignRefundsRequest) error {
	t := h.loadTransfer(req.TransferID)
	t.Status = "RECEIVER_REFUND_SIGNED"
	return nil
}

func (h *TransferHandler) InitiateSettleReceiverKeyTweak(req *InitiateSettleReceiverKeyTweakRequest) error {
	t := h.loadTransfer(req.TransferID)
	t.Status = "RECEIVER_KEY_TWEAK_LOCKED"
	return nil
}
