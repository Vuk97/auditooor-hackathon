// fixture: negative - custom authorization binds chain and nonce scope.
package signingfixtures

import (
	"crypto/ed25519"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type InboundClaim struct {
	ChainID   string
	Nonce     uint64
	Sender    string
	Memo      string
	Amount    int64
	Signature []byte
	PubKey    ed25519.PublicKey
}

func ValidateInboundSignature(claim InboundClaim) bool {
	preimage := []byte(fmt.Sprintf("%s:%d:%s:%s:%d", claim.ChainID, claim.Nonce, claim.Sender, claim.Memo, claim.Amount))
	return ed25519.Verify(claim.PubKey, preimage, claim.Signature)
}

type MsgClaimReward struct {
	Nonce   uint64
	Claimer sdk.AccAddress
}

func (k msgServer) ClaimReward(ctx sdk.Context, msg *MsgClaimReward) (*MsgClaimRewardResponse, error) {
	if k.HasNonce(ctx, msg.Nonce) {
		return nil, ErrReplay
	}
	k.ConsumeNonce(ctx, msg.Nonce)
	k.payout(ctx, msg.Claimer)
	return &MsgClaimRewardResponse{}, nil
}
