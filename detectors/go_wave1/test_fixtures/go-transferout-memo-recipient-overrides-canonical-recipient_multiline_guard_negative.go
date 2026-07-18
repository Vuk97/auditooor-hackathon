package fixtures

import "errors"

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

func (k Keeper) HandleTransferOut(ctx Context, msg MsgTransferOut, memo Memo) error {
	if memo.Recipient !=
		msg.ToAddress {
		return errors.New("recipient mismatch")
	}
	recipient := memo.Recipient
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", recipient, msg.Amount)
}
