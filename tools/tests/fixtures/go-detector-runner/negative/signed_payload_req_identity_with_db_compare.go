// Pattern 15 — NEGATIVE fixture.
//
// Same shape as the positive fixture, but the body reads the DB-sourced
// sender identity via mimo.GetSingleTransferSender AND compares it
// against the request-supplied identity before calling
// ValidateTransferPackage. Signature verification then runs against the
// authoritative DB identity.
//
// Mirrors the post-fix shape introduced in SP-5998.
package fixturen

import (
	"context"
	"fmt"

	"github.com/spark/keys"
	"github.com/spark/mimo"
)

type FinalizeReqN struct {
	TransferId             string
	OwnerIdentityPublicKey []byte
	TransferPackage        *TransferPackageN
	UserSignature          []byte
}

type TransferPackageN struct {
	LeavesToSend []byte
}

type HandlerN struct{}

func (h *HandlerN) ValidateTransferPackage(ctx context.Context, transferID string, pkg *TransferPackageN, ownerPub keys.Public, isSwap bool) (map[string]struct{}, error) {
	return nil, nil
}

// FinalizeTransferWithTransferPackagePostFix — the defended shape.
func (h *HandlerN) FinalizeTransferWithTransferPackagePostFix(ctx context.Context, req *FinalizeReqN, transfer interface{}) error {
	senderPubkey, err := mimo.GetSingleTransferSender(ctx, transfer)
	if err != nil {
		return err
	}
	reqOwnerPub, err := keys.ParsePublicKey(req.OwnerIdentityPublicKey)
	if err != nil {
		return err
	}
	if !reqOwnerPub.Equals(senderPubkey) {
		return fmt.Errorf("owner_identity_public_key in request does not match the transfer sender identity")
	}
	if _, err := h.ValidateTransferPackage(ctx, req.TransferId, req.TransferPackage, senderPubkey, true); err != nil {
		return err
	}
	_ = req.UserSignature
	return nil
}
