package negative

// Negative fixture: correct ordering — insurance-fund transfer precedes
// UpdateSubaccounts. Detector must NOT fire.

type Ctx struct{ dummy int }

type bankKeeperT struct{}
type subaKeeperT struct{}

func (bankKeeperT) SendCoins(ctx Ctx, from, to string, amt int64) error { return nil }
func (subaKeeperT) UpdateSubaccounts(ctx Ctx, updates []int) error      { return nil }
func (subaKeeperT) TransferInsuranceFundPayments(ctx Ctx, delta int64, perpID uint32) error {
	return nil
}

type Keeper struct {
	bankKeeper       bankKeeperT
	subaccountKeeper subaKeeperT
}

func (k *Keeper) persistLiquidationMatchCorrect(ctx Ctx) error {
	// Insurance fund moves first, then subaccount accounting.
	if err := k.subaccountKeeper.TransferInsuranceFundPayments(ctx, 100, 0); err != nil {
		return err
	}
	if err := k.subaccountKeeper.UpdateSubaccounts(ctx, nil); err != nil {
		return err
	}
	return nil
}

func (k *Keeper) updateOnlyPath(ctx Ctx) error {
	// Liquidation path without any insurance-fund interaction — no flag.
	return k.subaccountKeeper.UpdateSubaccounts(ctx, nil)
}
