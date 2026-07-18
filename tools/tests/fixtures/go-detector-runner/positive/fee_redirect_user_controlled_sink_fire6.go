package positive

type Context struct{}
type Coins struct{}
type AccAddress string

const FeeCollectorName = "fee_collector"

type MsgSettleTrade struct {
	ProtocolFee Coins
}

func (m MsgSettleTrade) GetSigners() []AccAddress {
	return []AccAddress{"attacker"}
}

type BankKeeper interface {
	SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error
}

type Keeper struct {
	bankKeeper BankKeeper
}

// Fire6 positive: the signer controls collector, then protocolFee is sent
// there without checking against the configured fee collector.
func (k Keeper) SettleProtocolFee(ctx Context, msg MsgSettleTrade) error {
	signers := msg.GetSigners()
	collector := signers[0]
	protocolFee := msg.ProtocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeeCollectorName, collector, protocolFee)
}
