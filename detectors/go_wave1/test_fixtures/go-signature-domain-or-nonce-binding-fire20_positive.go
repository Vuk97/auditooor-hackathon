package signingfixtures

import (
	"crypto/ed25519"
	"fmt"
)

// Confirmed source:
// findings-go:solodit-58650-zetachain-solana-withdraw-nonce-not-incremented
// Sherlock M-15, ZetaChain Cross-Chain: failed Solana withdrawal does not
// advance the nonce, leaving subsequent withdrawals blocked.
type Fire20WithdrawMsg struct {
	Sender    string
	Receiver  string
	Amount    int64
	Nonce     uint64
	Signature []byte
	PubKey    ed25519.PublicKey
}

type Fire20BridgeKeeper struct{}

func (k Fire20BridgeKeeper) VerifySignature(pub ed25519.PublicKey, payload []byte, sig []byte) bool {
	return ed25519.Verify(pub, payload, sig)
}

func (k Fire20BridgeKeeper) SubmitSolanaWithdrawal(ctx any, receiver string, amount int64) error {
	return nil
}

func (k Fire20BridgeKeeper) MarkWithdrawalFailed(ctx any, sender string, nonce uint64) error {
	return nil
}

func (k Fire20BridgeKeeper) MarkWithdrawalSubmitted(ctx any, sender string, nonce uint64) error {
	return nil
}

func (k Fire20BridgeKeeper) WithdrawSolana(ctx any, msg Fire20WithdrawMsg) error {
	payload := []byte(fmt.Sprintf("%s:%s:%d", msg.Sender, msg.Receiver, msg.Amount))
	if !k.VerifySignature(msg.PubKey, payload, msg.Signature) {
		return k.MarkWithdrawalFailed(ctx, msg.Sender, msg.Nonce)
	}

	if err := k.SubmitSolanaWithdrawal(ctx, msg.Receiver, msg.Amount); err != nil {
		return k.MarkWithdrawalFailed(ctx, msg.Sender, msg.Nonce)
	}

	return k.MarkWithdrawalSubmitted(ctx, msg.Sender, msg.Nonce)
}
