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

func (k Keeper) HandleTransferOut(ctx Context, msg MsgTransferOut, memo Memo) error {
	if memo.Recipient != msg.ToAddress {
		return nil
	}
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", memo.Recipient, msg.Amount)
}

func (k Keeper) HandleTransferOutDiagnosticOnly(ctx Context, msg MsgTransferOut, memo Memo) error {
	_ = ctx
	_ = msg
	_ = memo
	diagnostic := `bridge audit: SendCoinsFromModuleToAccount(ctx, "bridge", memo.Recipient, msg.Amount) must compare memo.Recipient with msg.ToAddress`
	_ = diagnostic
	return nil
}
