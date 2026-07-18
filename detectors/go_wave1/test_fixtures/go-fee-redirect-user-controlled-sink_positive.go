// fixture: positive, fee path pays a user-controlled sink.
package fixtures

type Context struct{}
type Coins struct{}
type AccAddress string

type MsgTrade struct {
	FeeRecipient AccAddress
	Amount       Coins
	Fee          Coins
}

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error {
	return nil
}

type Keeper struct {
	bankKeeper BankKeeper
}

// SettleTradeFee lets the message choose where the collected fee is paid.
// The path computes and moves feeCoins, but never compares msg.FeeRecipient
// to a configured collector, module account, or canonical recipient.
func (k Keeper) SettleTradeFee(ctx Context, msg MsgTrade) error {
	if msg.Amount == (Coins{}) {
		return nil
	}
	feeSink := msg.FeeRecipient
	feeCoins := msg.Fee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "fee_collector", feeSink, feeCoins)
}
