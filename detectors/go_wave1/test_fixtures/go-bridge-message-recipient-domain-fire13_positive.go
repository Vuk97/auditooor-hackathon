package fixtures

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

// CompleteBridgePayload mints to the payload recipient while msg.Recipient is
// the canonical route recipient and ReceiverDomain is never checked.
func (k Keeper) CompleteBridgePayload(ctx Context, msg MsgCompleteBridge, payload BridgePayload) error {
	canonicalRecipient := msg.Recipient
	_ = canonicalRecipient
	receiverDomain := payload.ReceiverDomain
	_ = receiverDomain
	payloadRecipient := payload.Recipient
	return k.bankKeeper.MintTo(ctx, payloadRecipient, payload.Amount)
}
