// Pattern 17 — NEGATIVE fixture.
//
// Same shape as the positive fixture, but the body invokes BOTH the
// pre-persist in-memory matcher (verifySenderKeyTweakProofsMatch) AND the
// post-persist DB-backed validator (validateKeyTweakProofs) before
// committing key tweaks.
//
// Mirrors the post-fix shape introduced in SP-5589.
package fixturen

import (
	"context"

	pb "github.com/spark/proto"
)

type TransferN struct {
	ID string
}

type BaseHandlerN struct{}

func verifySenderKeyTweakProofsMatch(keyTweakMap map[string]*pb.SendLeafKeyTweak, senderKeyTweakProofs map[string]*pb.SecretProof) error {
	return nil
}

func (h *BaseHandlerN) validateKeyTweakProofs(ctx context.Context, transfer *TransferN, senderKeyTweakProofs map[string]*pb.SecretProof) error {
	return nil
}

func (h *BaseHandlerN) commitSenderKeyTweaks(ctx context.Context, transfer *TransferN) (*TransferN, error) {
	return transfer, nil
}

// InitiateTransferDefended — the defended shape: pre-persist match plus
// post-persist validate.
func (h *BaseHandlerN) InitiateTransferDefended(ctx context.Context, transferID string, keyTweakMap map[string]*pb.SendLeafKeyTweak, senderKeyTweakProofs map[string]*pb.SecretProof) (*TransferN, error) {
	// Pre-persist in-memory match.
	if err := verifySenderKeyTweakProofsMatch(keyTweakMap, senderKeyTweakProofs); err != nil {
		return nil, err
	}
	transfer := &TransferN{ID: transferID}
	// Persist key tweaks.
	if _, err := h.commitSenderKeyTweaks(ctx, transfer); err != nil {
		return nil, err
	}
	// Post-persist DB-backed validate.
	if err := h.validateKeyTweakProofs(ctx, transfer, senderKeyTweakProofs); err != nil {
		return nil, err
	}
	return transfer, nil
}
