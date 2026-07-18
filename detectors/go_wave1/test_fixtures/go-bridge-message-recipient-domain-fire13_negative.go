package fixtures

import "errors"

type Context struct{}
type Coins struct{}
type AccAddress string

type BridgePayload struct {
	Recipient      AccAddress
	ReceiverDomain uint32
	Amount         Coins
}

type MsgCompleteBridge struct {
	Recipient AccAddress
	Amount    Coins
}

type BankKeeper struct{}

func (BankKeeper) MintTo(Context, AccAddress, Coins) error {
	return nil
}

type Keeper struct {
	bankKeeper  BankKeeper
	localDomain uint32
}

func (k Keeper) CompleteBridgePayload(ctx Context, msg MsgCompleteBridge, payload BridgePayload) error {
	canonicalRecipient := msg.Recipient
	payloadRecipient := payload.Recipient
	receiverDomain := payload.ReceiverDomain
	if payloadRecipient != canonicalRecipient {
		return errors.New("recipient mismatch")
	}
	if receiverDomain != k.localDomain {
		return errors.New("receiver domain mismatch")
	}
	return k.bankKeeper.MintTo(ctx, payloadRecipient, payload.Amount)
}
