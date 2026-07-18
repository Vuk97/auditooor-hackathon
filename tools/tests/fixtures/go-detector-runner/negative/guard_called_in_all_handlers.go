// Pattern 2 — NEGATIVE fixture (sharpened arm).
//
// Same package shape as guard_only_one_path_validate_handlers.go but the
// project-specific guard validateTransferLeavesNotExitedToL1 IS invoked
// from every status-mutating handler. Sharpened detector arm must NOT
// fire (and the file-default arm must also NOT fire because no default
// guard name is used).
package fixturephn

type TransferN struct {
	Status string
}

type TransferHandlerN struct{}

type ClaimReqA struct{ TransferID string }
type ClaimReqB struct{ TransferID string }
type ClaimReqC struct{ TransferID string }
type ClaimReqD struct{ TransferID string }

func (h *TransferHandlerN) loadTransfer(_ string) *TransferN { return &TransferN{} }

func (h *TransferHandlerN) validateTransferLeavesNotExitedToL1(t *TransferN, op string) error {
	_ = t
	_ = op
	return nil
}

func (h *TransferHandlerN) ClaimA(req *ClaimReqA) error {
	t := h.loadTransfer(req.TransferID)
	if err := h.validateTransferLeavesNotExitedToL1(t, "a"); err != nil {
		return err
	}
	t.Status = "A"
	return nil
}

func (h *TransferHandlerN) ClaimB(req *ClaimReqB) error {
	t := h.loadTransfer(req.TransferID)
	if err := h.validateTransferLeavesNotExitedToL1(t, "b"); err != nil {
		return err
	}
	t.Status = "B"
	return nil
}

func (h *TransferHandlerN) ClaimC(req *ClaimReqC) error {
	t := h.loadTransfer(req.TransferID)
	if err := h.validateTransferLeavesNotExitedToL1(t, "c"); err != nil {
		return err
	}
	t.Status = "C"
	return nil
}

func (h *TransferHandlerN) ClaimD(req *ClaimReqD) error {
	t := h.loadTransfer(req.TransferID)
	if err := h.validateTransferLeavesNotExitedToL1(t, "d"); err != nil {
		return err
	}
	t.Status = "D"
	return nil
}
