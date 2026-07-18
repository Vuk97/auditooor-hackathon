// Pattern 17 — POSITIVE fixture for
//   go.spark.cross_so.tweak_guard_pre_post_persist
//
// CommitSenderKeyTweaksPostOnly only invokes the post-persist DB-backed
// validator (validateKeyTweakProofs). The pre-persist in-memory matcher
// (verifySenderKeyTweakProofsMatch) is missing — the function commits a
// key-tweak persistence step (commitSenderKeyTweaks +
// transferLeaf.Update().Save) using the proofs without first matching
// the coordinator's plaintext proofs against independently-decrypted
// package proofs.
//
// Mirrors SP-5589 (``dae7686f2c``) on buildonspark/spark — pre-fix the
// receiving SO ran only one of the two halves.
package fixture

import (
	"context"

	pb "github.com/spark/proto"
)

type Transfer struct {
	ID string
}

type BaseHandler struct{}

func (h *BaseHandler) validateKeyTweakProofs(ctx context.Context, transfer *Transfer, senderKeyTweakProofs map[string]*pb.SecretProof) error {
	return nil
}

func (h *BaseHandler) commitSenderKeyTweaks(ctx context.Context, transfer *Transfer) (*Transfer, error) {
	return transfer, nil
}

// CommitSenderKeyTweaksPostOnly — the vulnerable shape: post-persist
// validator only, no pre-persist matcher.
func (h *BaseHandler) CommitSenderKeyTweaksPostOnly(ctx context.Context, transferID string, senderKeyTweakProofs map[string]*pb.SecretProof) (*Transfer, error) {
	transfer := &Transfer{ID: transferID}
	err := h.validateKeyTweakProofs(ctx, transfer, senderKeyTweakProofs)
	if err != nil {
		return nil, err
	}
	transferLeaf := struct {
		Update func() interface{ Save(context.Context) error }
	}{}
	_ = transferLeaf
	// Persist via commitSenderKeyTweaks - no in-memory match performed.
	return h.commitSenderKeyTweaks(ctx, transfer)
}
