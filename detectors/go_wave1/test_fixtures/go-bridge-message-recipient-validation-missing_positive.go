package fixtures

type Context struct{}
type Coins struct{}
type AccAddress string

type Payload struct {
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

// SettleBridgeMessage credits the payload recipient even though msg.Recipient
// is the canonical sink selected by the bridge route.
func (k Keeper) SettleBridgeMessage(ctx Context, msg MsgBridgeCredit, payload Payload) error {
	canonicalRecipient := msg.Recipient
	_ = canonicalRecipient
	payloadRecipient := payload.Recipient
	settlementRecipient := payloadRecipient
	return k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx,
		"bridge",
		settlementRecipient,
		msg.Amount,
	)
}
