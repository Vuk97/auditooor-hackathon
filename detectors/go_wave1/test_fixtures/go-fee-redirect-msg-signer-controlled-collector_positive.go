// fixture: positive, fee path pays a signer-derived collector.
package fixtures

type Context struct{}
type Coins struct{}
type AccAddress string

const FeeCollectorName = "fee_collector"

type MsgClaimFeeReward struct {
	Sender      AccAddress
	ProtocolFee Coins
}

func (m MsgClaimFeeReward) GetSigners() []AccAddress {
	return []AccAddress{m.Sender}
}

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error {
	return nil
}

type Keeper struct {
	bankKeeper BankKeeper
}

// ClaimProtocolFeeReward incorrectly lets the message signer become the
// collector for protocolFee. No configured collector, treasury, module account,
// or allowlisted sink is consulted before the fee-like value is sent.
func (k Keeper) ClaimProtocolFeeReward(ctx Context, msg MsgClaimFeeReward) error {
	signers := msg.GetSigners()
	collector := signers[0]
	protocolFee := msg.ProtocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeeCollectorName, collector, protocolFee)
}
