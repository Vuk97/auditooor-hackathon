// fixture: negative, fee paths use or validate configured recipients.
package fixtures

type Context struct{}
type Coins struct{}
type AccAddress string

type MsgTrade struct {
	FeeRecipient AccAddress
	Recipient    AccAddress
	Amount       Coins
	Fee          Coins
}

type FeeParams struct {
	FeeCollector AccAddress
}

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error {
	return nil
}

type Keeper struct {
	bankKeeper BankKeeper
}

// Configured collector is the sink, so no user-controlled redirect exists.
func (k Keeper) SettleTradeFeeToCollector(ctx Context, msg MsgTrade, params FeeParams) error {
	collector := params.FeeCollector
	feeCoins := msg.Fee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "fee_collector", collector, feeCoins)
}

// Equality to configured collector is validated before the fee sink is used.
func (k Keeper) SettleTradeFeeWithCollectorCheck(ctx Context, msg MsgTrade, params FeeParams) error {
	feeSink := msg.FeeRecipient
	if feeSink != params.FeeCollector {
		return nil
	}
	feeCoins := msg.Fee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "fee_collector", feeSink, feeCoins)
}

// Ordinary user withdrawals are not fee payouts and must stay silent.
func (k Keeper) Withdraw(ctx Context, msg MsgTrade) error {
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "escrow", msg.Recipient, msg.Amount)
}
