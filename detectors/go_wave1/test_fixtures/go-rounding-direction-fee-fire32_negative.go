// fixture: negative - rounding direction is explicit or the rounded value is guarded.
package keeper

import "errors"

const ProtocolFeeBps uint64 = 25

type Coin struct {
	Denom  string
	Amount uint64
}

type Bank struct{}

func (b Bank) SendCoinsFromAccountToModule(user string, module string, coin Coin) error {
	return nil
}

type Position struct {
	User            string
	Notional       uint64
	Debt           uint64
	Collateral     uint64
	MaintenanceBps uint64
}

type Keeper struct {
	bank            Bank
	ProtocolRevenue uint64
	Debts           map[string]uint64
	DebugBucket     uint64
}

func ceilDiv(numerator uint64, denominator uint64) uint64 {
	return (numerator + denominator - 1) / denominator
}

// ChargeTradingFeeRoundedUp pulls a ceil-rounded protocol fee.
func (k Keeper) ChargeTradingFeeRoundedUp(user string, notional uint64) error {
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

// ApplyDebtWriteExact rejects non-exact debt scaling before writing state.
func (k Keeper) ApplyDebtWriteExact(pos Position) error {
	if (pos.Debt*105)%100 != 0 {
		return errors.New("non-exact debt scaling")
	}
	penaltyDebt := pos.Debt * 105 / 100
	k.Debts[pos.User] = penaltyDebt
	return nil
}

// AllowWithdrawAfterRoundedDebtGuarded rejects zero rounded requirements.
func (k Keeper) AllowWithdrawAfterRoundedDebtGuarded(pos Position, withdraw uint64) error {
	requiredDebt := pos.Debt * pos.MaintenanceBps / 10_000
	if requiredDebt == 0 {
		return errors.New("zero required debt")
	}
	if pos.Collateral-withdraw >= requiredDebt {
		return nil
	}
	return errors.New("insolvent")
}

// StoreDebugBucket uses division for non-value debug telemetry only.
func (k Keeper) StoreDebugBucket(index uint64) error {
	bucket := index / 10
	k.DebugBucket = bucket
	return nil
}
