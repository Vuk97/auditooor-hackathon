// fixture: negative - safe rounding direction, exactness guards, or non-value sinks.
package keeper

import "errors"

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

type Keeper struct {
	bank            Bank
	ProtocolRevenue uint64
	TotalShares     uint64
	TotalAssets     uint64
	Shares          map[string]uint64
	Debts           map[string]uint64
	DebugBucket     uint64
}

func ceilDiv(numerator uint64, denominator uint64) uint64 {
	return (numerator + denominator - 1) / denominator
}

func floorDiv(numerator uint64, denominator uint64) uint64 {
	return numerator / denominator
}

// ChargeTradingFeeCeilProtectsProtocol ceil-rounds the protocol fee.
func (k Keeper) ChargeTradingFeeCeilProtectsProtocol(user string, notional uint64) error {
	fee := ceilDiv(notional*ProtocolFeeBps, 10_000)
	if fee == 0 {
		return errors.New("zero fee")
	}
	if err := k.bank.SendCoinsFromAccountToModule(user, "treasury", Coin{Denom: "uusd", Amount: fee}); err != nil {
		return err
	}
	k.ProtocolRevenue += fee
	return nil
}

// MintSharesFullPrecision uses multiplication before division and guards zero.
func (k Keeper) MintSharesFullPrecision(user string, assets uint64) error {
	shares := assets * k.TotalShares / k.TotalAssets
	if shares == 0 {
		return errors.New("zero shares")
	}
	if err := k.bank.SendCoinsFromAccountToModule(user, "vault", Coin{Denom: "uusd", Amount: assets}); err != nil {
		return err
	}
	k.Shares[user] += shares
	return nil
}

// ClaimRewardFloorDoesNotFavorAttacker floors value leaving protocol custody.
func (k Keeper) ClaimRewardFloorDoesNotFavorAttacker(user string, accrued uint64) error {
	reward := floorDiv(accrued, RewardScale)
	if err := k.bank.SendCoinsFromModuleToAccount("rewards", user, Coin{Denom: "uusd", Amount: reward}); err != nil {
		return err
	}
	return nil
}

// RepayWithFloorCredit does not over-reduce debt for the payer.
func (k Keeper) RepayWithFloorCredit(user string, payment uint64, price uint64) error {
	debtCredit := floorDiv(payment*RewardScale, price)
	if err := k.bank.SendCoinsFromAccountToModule(user, "debt", Coin{Denom: "uusd", Amount: payment}); err != nil {
		return err
	}
	k.Debts[user] -= debtCredit
	return nil
}

// ApplyDebtWriteExact rejects non-exact debt scaling before writing state.
func (k Keeper) ApplyDebtWriteExact(user string, debt uint64) error {
	if (debt*105)%100 != 0 {
		return errors.New("non-exact debt scaling")
	}
	penaltyDebt := debt * 105 / 100
	k.Debts[user] = penaltyDebt
	return nil
}

// StoreDebugBucket writes a rounded metric to debug telemetry only.
func (k Keeper) StoreDebugBucket(index uint64) error {
	bucket := index / 10
	k.DebugBucket = bucket
	return nil
}
