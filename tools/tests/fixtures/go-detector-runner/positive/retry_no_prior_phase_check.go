// Pattern 16 — POSITIVE fixture for
//   go.spark.retry.prior_phase_commit_check
//
// ClaimTransferPreFix unconditionally extracts and decrypts the
// coordinator portion of the claim package's KeyTweakPackage. There is no
// gate that prefers stored material when the receiver has already locked
// Phase 1 — useStoredKeyTweaks / alreadyLocked are absent and there is no
// compare against TransferReceiverStatusKeyTweakLocked / similar.
//
// Mirrors SP-5498 (``f26284dd5f``) on buildonspark/spark.
package fixture

import (
	"context"

	eciesgo "github.com/ecies/go/v2"
	pb "github.com/spark/proto"
	"google.golang.org/protobuf/proto"
)

type ClaimRequest struct {
	TransferId   string
	ClaimPackage *pb.ClaimPackage
}

type ClaimHandler struct {
	config struct {
		Identifier         string
		IdentityPrivateKey privateKey
	}
}

type privateKey struct{}

func (privateKey) Serialize() []byte { return nil }

// ClaimTransferPreFix — the vulnerable shape: decrypt coordinator package
// without any prior-phase commit gate.
func (h *ClaimHandler) ClaimTransferPreFix(ctx context.Context, req *ClaimRequest) error {
	claimPackage := req.ClaimPackage
	coordinatorKeyTweaks := claimPackage.KeyTweakPackage[h.config.Identifier]
	if len(coordinatorKeyTweaks) == 0 {
		return nil
	}
	decryptionPrivateKey := eciesgo.NewPrivateKeyFromBytes(h.config.IdentityPrivateKey.Serialize())
	decrypted, err := eciesgo.Decrypt(decryptionPrivateKey, coordinatorKeyTweaks)
	if err != nil {
		return err
	}
	claimKeyTweaks := &pb.ClaimLeafKeyTweaks{}
	if err := proto.Unmarshal(decrypted, claimKeyTweaks); err != nil {
		return err
	}
	for _, leafTweak := range claimKeyTweaks.LeavesToReceive {
		_ = leafTweak
	}
	return nil
}
