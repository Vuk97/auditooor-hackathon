package signingfixtures

import (
	"crypto/ed25519"
	"fmt"
)

type ScopedContext interface {
	ChainID() string
}

type ScopedClaim struct {
	Sender        string
	Memo          string
	Amount        int64
	AccountNumber uint64
	Sequence      uint64
	Signature     []byte
	PubKey        ed25519.PublicKey
}

type SignDoc struct {
	ChainID       string
	AccountNumber uint64
	Sequence      uint64
	Payload       string
}

func ValidateInboundSignatureScoped(ctx ScopedContext, claim ScopedClaim) bool {
	doc := SignDoc{
		ChainID:       ctx.ChainID(),
		AccountNumber: claim.AccountNumber,
		Sequence:      claim.Sequence,
		Payload:       fmt.Sprintf("%s:%s:%d", claim.Sender, claim.Memo, claim.Amount),
	}
	preimage := []byte(fmt.Sprintf("%s:%d:%d:%s", doc.ChainID, doc.AccountNumber, doc.Sequence, doc.Payload))
	return ed25519.Verify(claim.PubKey, preimage, claim.Signature)
}
