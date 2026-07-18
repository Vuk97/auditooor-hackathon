package signingfixtures

import (
	"crypto/ed25519"
	"fmt"
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
