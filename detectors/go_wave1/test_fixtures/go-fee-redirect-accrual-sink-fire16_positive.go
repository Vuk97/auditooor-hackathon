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
	bankKeeper     BankKeeper
	feeEntitlement map[AccAddress]Coins
}

type SettleFeeMsg struct {
	Beneficiary AccAddress
	FeeSink     AccAddress
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

func (k Keeper) SettleAccruedProtocolFee(ctx Context, msg SettleFeeMsg) error {
	protocolFee := CalculateProtocolFee()
	k.feeEntitlement[msg.Beneficiary] += protocolFee
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, FeePoolName, msg.FeeSink, protocolFee)
}

func (k Keeper) DistributeConfigReward(ctx Context, cfg RewardConfig, treasury AccAddress) error {
	rewardAmount := PendingReward()
	rewardSink := cfg.RewardSink
	return k.bankKeeper.SendCoins(ctx, treasury, rewardSink, rewardAmount)
}
