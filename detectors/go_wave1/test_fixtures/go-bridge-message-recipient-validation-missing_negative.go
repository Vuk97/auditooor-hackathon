package fixtures

import "errors"

type Context struct{}
type Coins struct{}
type AccAddress string

type Payload struct {
	Recipient AccAddress
}

type Memo struct {
	Recipient AccAddress
}

type MsgBridgeCredit struct {
	Recipient AccAddress
	Amount    Coins
}

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error {
	return nil
}

type Keeper struct {
	bankKeeper BankKeeper
}

func (k Keeper) SettleBridgeMessage(ctx Context, msg MsgBridgeCredit, payload Payload) error {
	canonicalRecipient := msg.Recipient
	payloadRecipient := payload.Recipient
	if payloadRecipient != canonicalRecipient {
		return errors.New("recipient mismatch")
	}
	return k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx,
		"bridge",
		payloadRecipient,
		msg.Amount,
	)
}

func (k Keeper) CreditCanonicalSinkOnly(ctx Context, msg MsgBridgeCredit, memo Memo) error {
	_ = memo.Recipient
	sinkRecipient := msg.Recipient
	return k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx,
		"bridge",
		sinkRecipient,
		msg.Amount,
	)
}
