// fixture: positive - signature bytes and nonce fields lack replay scope.
package signingfixtures

import (
	"crypto/ed25519"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type InboundClaim struct {
	Sender    string
	Memo      string
	Amount    int64
	Signature []byte
	PubKey    ed25519.PublicKey
}

func ValidateInboundSignature(claim InboundClaim) bool {
	preimage := []byte(fmt.Sprintf("%s:%s:%d", claim.Sender, claim.Memo, claim.Amount))
	return ed25519.Verify(claim.PubKey, preimage, claim.Signature)
}

type MsgClaimReward struct {
	Nonce   uint64
	Claimer sdk.AccAddress
}

func (k msgServer) ClaimReward(ctx sdk.Context, msg *MsgClaimReward) (*MsgClaimRewardResponse, error) {
	id := msg.Nonce
	_ = id
	k.payout(ctx, msg.Claimer)
	return &MsgClaimRewardResponse{}, nil
}
