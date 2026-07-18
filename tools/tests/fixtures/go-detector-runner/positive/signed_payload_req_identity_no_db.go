// Pattern 15 — POSITIVE fixture for
//   go.spark.signed_payload.req_identity_validator
//
// FinalizeTransferWithTransferPackagePreFix passes the request-supplied
// owner identity public key directly to ValidateTransferPackage. The
// signature verification inside the validator therefore trusts the
// CALLER's claimed identity rather than the DB-stored sender identity.
//
// Mirrors SP-5998 (``6daafae89b``) on buildonspark/spark.
package fixture

import (
	"context"

	"github.com/spark/keys"
)

type FinalizeReq struct {
	TransferId             string
	OwnerIdentityPublicKey []byte
	TransferPackage        *TransferPackage
	UserSignature          []byte
}

type TransferPackage struct {
	LeavesToSend []byte
}

type Handler struct{}

func (h *Handler) ValidateTransferPackage(ctx context.Context, transferID string, pkg *TransferPackage, ownerPub keys.Public, isSwap bool) (map[string]struct{}, error) {
	return nil, nil
}

// FinalizeTransferWithTransferPackagePreFix — the vulnerable shape.
func (h *Handler) FinalizeTransferWithTransferPackagePreFix(ctx context.Context, req *FinalizeReq) error {
	reqOwnerPub, err := keys.ParsePublicKey(req.OwnerIdentityPublicKey)
	if err != nil {
		return err
	}
	// No DB-sourced sender identity read. No equality compare against the
	// stored sender identity. Just pass req identity directly.
	if _, err := h.ValidateTransferPackage(ctx, req.TransferId, req.TransferPackage, reqOwnerPub, true); err != nil {
		return err
	}
	_ = req.UserSignature
	return nil
}
