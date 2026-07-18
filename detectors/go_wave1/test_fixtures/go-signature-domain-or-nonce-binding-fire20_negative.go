package signingfixtures

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

type Fire20ScopedWithdrawMsg struct {
	Signer    string
	Receiver  string
	Amount    int64
	Nonce     uint64
	Signature []byte
	PubKey    ed25519.PublicKey
}

type Fire20ScopedContext interface {
	ChainID() string
}

type Fire20ScopedBridgeKeeper struct{}

func (k Fire20ScopedBridgeKeeper) HasNonce(ctx Fire20ScopedContext, signer string, nonce uint64) bool {
	return false
}

func (k Fire20ScopedBridgeKeeper) ConsumeNonce(ctx Fire20ScopedContext, signer string, nonce uint64) error {
	return nil
}

func (k Fire20ScopedBridgeKeeper) SubmitSolanaWithdrawal(ctx Fire20ScopedContext, receiver string, amount int64) error {
	return nil
}

func (k Fire20ScopedBridgeKeeper) MarkWithdrawalSubmitted(ctx Fire20ScopedContext, signer string, nonce uint64) error {
	return nil
}

func (k Fire20ScopedBridgeKeeper) WithdrawSolanaScoped(ctx Fire20ScopedContext, msg Fire20ScopedWithdrawMsg) error {
	const domain = "zetachain-solana-withdraw-v1"
	const action = "withdraw"

	if k.HasNonce(ctx, msg.Signer, msg.Nonce) {
		return errors.New("nonce already consumed")
	}

	payload := []byte(fmt.Sprintf(
		"%s:%s:%s:%s:%d:%d:%s",
		ctx.ChainID(),
		domain,
		action,
		msg.Signer,
		msg.Amount,
		msg.Nonce,
		msg.Receiver,
	))
	if !ed25519.Verify(msg.PubKey, payload, msg.Signature) {
		return errors.New("invalid signer")
	}
	if err := k.ConsumeNonce(ctx, msg.Signer, msg.Nonce); err != nil {
		return err
	}
	if err := k.SubmitSolanaWithdrawal(ctx, msg.Receiver, msg.Amount); err != nil {
		return err
	}
	return k.MarkWithdrawalSubmitted(ctx, msg.Signer, msg.Nonce)
}
