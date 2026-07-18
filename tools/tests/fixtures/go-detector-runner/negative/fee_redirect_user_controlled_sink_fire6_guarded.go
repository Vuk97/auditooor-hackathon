package negative

import "errors"

type Context struct{}
type Coins struct{}
type AccAddress string

const FeeCollectorName = "fee_collector"

type MsgSettleTrade struct {
	ProtocolFee Coins
}

func (m MsgSettleTrade) GetSigners() []AccAddress {
	return []AccAddress{"user"}
}

type Params struct {
	FeeCollector AccAddress
	Treasury     AccAddress
}

type BankKeeper interface {
	SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error
}

type Keeper struct {
	bankKeeper BankKeeper
}

// Configured collector is the sink, so the signer cannot redirect fees.
func (k Keeper) SettleProtocolFeeToConfiguredCollector(ctx Context, msg MsgSettleTrade, params Params) error {
	_ = msg.GetSigners()
	collector := params.FeeCollector
	protocolFee := msg.ProtocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeeCollectorName, collector, protocolFee)
}

// Signer-derived collector is accepted only after matching configured collector.
func (k Keeper) SettleProtocolFeeWithCollectorGuard(ctx Context, msg MsgSettleTrade, params Params) error {
	signers := msg.GetSigners()
	collector := signers[0]
	if collector != params.FeeCollector {
		return errors.New("collector is not configured")
	}
	protocolFee := msg.ProtocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeeCollectorName, collector, protocolFee)
}

// Treasury sink is configured by params and is not user-controlled.
func (k Keeper) SettleProtocolFeeToTreasury(ctx Context, msg MsgSettleTrade, params Params) error {
	protocolFee := msg.ProtocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeeCollectorName, params.Treasury, protocolFee)
}
