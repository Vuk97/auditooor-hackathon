// fixture: positive - rounding is applied on the attacker-favorable side.
package keeper

const (
	ProtocolFeeBps uint64 = 25
	RewardScale    uint64 = 1_000_000
)

type Coin struct {
	Denom  string
	Amount uint64
}

type Bank struct{}

func (b Bank) SendCoinsFromAccountToModule(user string, module string, coin Coin) error {
	return nil
}

func (b Bank) SendCoinsFromModuleToAccount(module string, user string, coin Coin) error {
	return nil
}

type Position struct {
	User            string
	Borrower        string
	Debt            uint64
	Collateral      uint64
	MaintenanceBps  uint64
	LiquidationBps  uint64
	DiscountedPrice uint64
}

type Keeper struct {
	bank            Bank
	ProtocolRevenue uint64
	TotalShares     uint64
	TotalAssets     uint64
	Shares          map[string]uint64
	Debts           map[string]uint64
	Collateral      map[string]uint64
	Rewards         map[string]uint64
}

func ceilDiv(numerator uint64, denominator uint64) uint64 {
	return (numerator + denominator - 1) / denominator
}

// ChargeTradingFeeFloorsUnderpayment floors the protocol fee pulled from a user.
func (k Keeper) ChargeTradingFeeFloorsUnderpayment(user string, notional uint64) error {
	fee := notional * ProtocolFeeBps / 10_000
	if err := k.bank.SendCoinsFromAccountToModule(user, "treasury", Coin{Denom: "uusd", Amount: fee}); err != nil {
		return err
	}
	k.ProtocolRevenue += fee
	return nil
}

// MintSharesDivideEarly transfers assets but can mint zero shares.
func (k Keeper) MintSharesDivideEarly(user string, assets uint64) error {
	shares := assets / k.TotalAssets * k.TotalShares
	if err := k.bank.SendCoinsFromAccountToModule(user, "vault", Coin{Denom: "uusd", Amount: assets}); err != nil {
		return err
	}
	k.Shares[user] += shares
	k.TotalShares += shares
	return nil
}

// ClaimRewardCeilOverpaysUser ceil-rounds value leaving protocol custody.
func (k Keeper) ClaimRewardCeilOverpaysUser(user string, emission uint64) error {
	reward := ceilDiv(k.Rewards[user]*emission, RewardScale)
	if err := k.bank.SendCoinsFromModuleToAccount("rewards", user, Coin{Denom: "uusd", Amount: reward}); err != nil {
		return err
	}
	k.Rewards[user] = 0
	return nil
}

// RepayWithCeilCredit reduces more user debt than the payment exactly covers.
func (k Keeper) RepayWithCeilCredit(user string, payment uint64, price uint64) error {
	debtCredit := ceilDiv(payment*RewardScale, price)
	if err := k.bank.SendCoinsFromAccountToModule(user, "debt", Coin{Denom: "uusd", Amount: payment}); err != nil {
		return err
	}
	k.Debts[user] -= debtCredit
	return nil
}

// LiquidateWithFloorCollateralSeizure under-seizes borrower collateral.
func (k Keeper) LiquidateWithFloorCollateralSeizure(pos Position, repayAmount uint64) error {
	collateralSeized := repayAmount * pos.LiquidationBps / pos.DiscountedPrice
	if err := k.bank.SendCoinsFromAccountToModule(pos.User, "debt", Coin{Denom: "uusd", Amount: repayAmount}); err != nil {
		return err
	}
	k.Collateral[pos.Borrower] -= collateralSeized
	return nil
}
