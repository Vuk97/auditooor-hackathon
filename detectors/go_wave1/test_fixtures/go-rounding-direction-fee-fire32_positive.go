// fixture: positive - fee, debt, and solvency math floor in user-favorable paths.
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
}

// ChargeTradingFee floors the protocol fee before pulling it from the user.
func (k Keeper) ChargeTradingFee(user string, notional uint64) error {
	fee := notional * ProtocolFeeBps / 10_000
	if err := k.bank.SendCoinsFromAccountToModule(user, "treasury", Coin{Denom: "uusd", Amount: fee}); err != nil {
		return err
	}
	k.ProtocolRevenue += fee
	return nil
}

// ApplyDebtWrite floors a liquidation penalty before updating borrower debt.
func (k Keeper) ApplyDebtWrite(pos Position) error {
	penaltyDebt := pos.Debt * 105 / 100
	k.Debts[pos.User] = penaltyDebt
	return nil
}

// AllowWithdrawAfterRoundedDebt floors required debt before a solvency check.
func (k Keeper) AllowWithdrawAfterRoundedDebt(pos Position, withdraw uint64) error {
	requiredDebt := pos.Debt * pos.MaintenanceBps / 10_000
	if pos.Collateral-withdraw >= requiredDebt {
		return nil
	}
	return errors.New("insolvent")
}
