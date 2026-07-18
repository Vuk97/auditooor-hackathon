// Pattern 16 — NEGATIVE fixture.
//
// Same shape as the positive fixture, but the body sets useStoredKeyTweaks
// based on the receiver status (KeyTweakLocked / KeyTweakApplied /
// RefundSigned all skip the fresh decrypt). The prior-phase commit gate
// is present.
//
// Mirrors the post-fix shape introduced in SP-5498 (f26284dd5f).
package fixturen

import (
	"context"

	eciesgo "github.com/ecies/go/v2"
	pb "github.com/spark/proto"
	st "github.com/spark/schema"
	"google.golang.org/protobuf/proto"
)

type ClaimRequestN struct {
	TransferId   string
	ClaimPackage *pb.ClaimPackage
}

type Receiver struct {
	Status st.TransferReceiverStatus
}

type ClaimHandlerN struct {
	config struct {
		Identifier         string
		IdentityPrivateKey privateKeyN
	}
}

type privateKeyN struct{}

func (privateKeyN) Serialize() []byte { return nil }

// ClaimTransferPostFix — the defended shape.
func (h *ClaimHandlerN) ClaimTransferPostFix(ctx context.Context, req *ClaimRequestN, receiver *Receiver) error {
	claimPackage := req.ClaimPackage
	useStoredKeyTweaks := false
	switch receiver.Status {
	case st.TransferReceiverStatusKeyTweakLocked,
		st.TransferReceiverStatusKeyTweakApplied,
		st.TransferReceiverStatusRefundSigned:
		useStoredKeyTweaks = true
	default:
	}
	coordinatorKeyTweaks := claimPackage.KeyTweakPackage[h.config.Identifier]
	if !useStoredKeyTweaks && len(coordinatorKeyTweaks) > 0 {
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
	}
	return nil
}
