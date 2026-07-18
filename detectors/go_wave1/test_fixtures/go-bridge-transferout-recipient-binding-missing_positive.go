package fixtures

type Context struct{}
type Coins struct{}
type AccAddress string

type Memo struct {
	Recipient AccAddress
}

type MsgTransferOut struct {
	ToAddress AccAddress
	Amount    Coins
}

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error {
	return nil
}

type Keeper struct {
	bankKeeper BankKeeper
}

// HandleTransferOut routes bridge funds to the memo recipient, but never binds
// it back to the canonical request recipient carried on the message.
func (k Keeper) HandleTransferOut(ctx Context, msg MsgTransferOut, memo Memo) error {
	if msg.Amount == (Coins{}) {
		return nil
	}
	expectedRecipient := msg.ToAddress
	_ = expectedRecipient
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", memo.Recipient, msg.Amount)
}
