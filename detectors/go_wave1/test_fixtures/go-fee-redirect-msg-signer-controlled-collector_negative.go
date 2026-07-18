// fixture: negative, fee paths use or validate configured collectors.
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

type FeeParams struct {
	FeeCollector AccAddress
	Treasury     AccAddress
}

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error {
	return nil
}

type Keeper struct {
	bankKeeper BankKeeper
}

// Configured collector is the sink, so the signer cannot redirect fees.
func (k Keeper) ClaimProtocolFeeRewardToCollector(ctx Context, msg MsgClaimFeeReward, params FeeParams) error {
	_ = msg.GetSigners()
	collector := params.FeeCollector
	protocolFee := msg.ProtocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeeCollectorName, collector, protocolFee)
}

// Signer-derived collector is compared to the configured collector before use.
func (k Keeper) ClaimProtocolFeeRewardWithCollectorCheck(ctx Context, msg MsgClaimFeeReward, params FeeParams) error {
	signers := msg.GetSigners()
	collector := signers[0]
	if collector != params.FeeCollector {
		return nil
	}
	protocolFee := msg.ProtocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeeCollectorName, collector, protocolFee)
}

// Treasury payout is configured by params, so it is not signer-controlled.
func (k Keeper) ClaimProtocolFeeRewardToTreasury(ctx Context, msg MsgClaimFeeReward, params FeeParams) error {
	protocolFee := msg.ProtocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeeCollectorName, params.Treasury, protocolFee)
}
