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

// HandleTransferOut trusts memo.Recipient as the paid destination even though
// msg.ToAddress already carries the canonical route recipient.
func (k Keeper) HandleTransferOut(ctx Context, msg MsgTransferOut, memo Memo) error {
	if msg.Amount == (Coins{}) {
		return nil
	}
	_ = "if memo.Recipient != msg.ToAddress { return nil }"
	memoRecipient := memo.Recipient
	recipient := memoRecipient
	_ = msg.ToAddress
	return k.bankKeeper.SendCoinsFromModuleToAccount(
		ctx,
		"bridge",
		recipient,
		msg.Amount,
	)
}
