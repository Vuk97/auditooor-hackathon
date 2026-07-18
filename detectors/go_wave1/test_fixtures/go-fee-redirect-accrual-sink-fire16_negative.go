package fixtures

type AccAddress string
type Coins int

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(ctx Context, module string, to AccAddress, amount Coins) error {
	return nil
}

func (BankKeeper) SendCoins(ctx Context, from AccAddress, to AccAddress, amount Coins) error {
	return nil
}

type Context struct{}

type Keeper struct {
	bankKeeper BankKeeper
}

type SettleFeeMsg struct {
	Beneficiary AccAddress
	FeeSink     AccAddress
}

type Params struct {
	FeeCollector AccAddress
	Treasury     AccAddress
}

type RewardConfig struct {
	RewardSink AccAddress
}

const FeePoolName = "fee_pool"

func CalculateProtocolFee() Coins {
	return 7
}

func PendingReward() Coins {
	return 11
}

func (k Keeper) IsAllowedRewardSink(ctx Context, sink AccAddress) bool {
	return sink == "reward_module"
}

func (k Keeper) SettleAccruedProtocolFeeFixedCollector(ctx Context, msg SettleFeeMsg, params Params) error {
	protocolFee := CalculateProtocolFee()
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeePoolName, params.FeeCollector, protocolFee)
}

func (k Keeper) SettleAccruedProtocolFeePolicyChecked(ctx Context, msg SettleFeeMsg, params Params) error {
	protocolFee := CalculateProtocolFee()
	if msg.FeeSink != params.FeeCollector {
		return nil
	}
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeePoolName, msg.FeeSink, protocolFee)
}

func (k Keeper) DistributeRewardWithAllowlist(ctx Context, cfg RewardConfig, params Params) error {
	rewardAmount := PendingReward()
	if !k.IsAllowedRewardSink(ctx, cfg.RewardSink) {
		return nil
	}
	return k.bankKeeper.SendCoins(ctx, params.Treasury, cfg.RewardSink, rewardAmount)
}
