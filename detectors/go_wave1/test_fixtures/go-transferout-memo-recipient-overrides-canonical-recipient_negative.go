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
	if memo.Recipient != msg.ToAddress {
		return errors.New("recipient mismatch")
	}
	recipient := memo.Recipient
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", recipient, msg.Amount)
}

func (k Keeper) HandleTransferOutRebound(ctx Context, msg MsgTransferOut, memo Memo) error {
	recipient := memo.Recipient
	recipient = msg.ToAddress
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", recipient, msg.Amount)
}

func (k Keeper) HandleTransferOutStringBait(ctx Context, msg MsgTransferOut, memo Memo) error {
	_ = memo
	_ = "memo.Recipient"
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", msg.ToAddress, msg.Amount)
}

func (k Keeper) ProcessPaymentCommentBait(ctx Context, msg MsgTransferOut, memo Memo) error {
	// transferOut bridge outbound msg.ToAddress
	_ = "msg.ToAddress"
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", memo.Recipient, msg.Amount)
}
