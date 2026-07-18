package positive

// Positive fixture: in the liquidation path, UpdateSubaccounts is called
// BEFORE the insurance-fund transfer. This inverts the invariant and the
// detector should flag.

type Ctx struct{ dummy int }

type bankKeeperT struct{}
type subaKeeperT struct{}

func (bankKeeperT) SendCoins(ctx Ctx, from, insuranceFund string, amt int64) error { return nil }
func (subaKeeperT) UpdateSubaccounts(ctx Ctx, updates []int) error                 { return nil }
func (subaKeeperT) TransferInsuranceFundPayments(ctx Ctx, delta int64, perpID uint32) error {
	return nil
}

type Keeper struct {
	bankKeeper       bankKeeperT
	subaccountKeeper subaKeeperT
}

func (k *Keeper) persistLiquidationMatchInverted(ctx Ctx) error {
	// BUG: subaccount accounting moves first, insurance-fund send happens after.
	if err := k.subaccountKeeper.UpdateSubaccounts(ctx, nil); err != nil {
		return err
	}
	// Now we credit/debit insurance fund — but state already mutated.
	if err := k.subaccountKeeper.TransferInsuranceFundPayments(ctx, 100, 0); err != nil {
		return err
	}
	return nil
}

func (k *Keeper) liquidateInvertedSendCoins(ctx Ctx) error {
	// Variant: explicit SendCoins to insuranceFund, still inverted.
	if err := k.subaccountKeeper.UpdateSubaccounts(ctx, nil); err != nil {
		return err
	}
	if err := k.bankKeeper.SendCoins(ctx, "user", "insuranceFundAddr", 50); err != nil {
		return err
	}
	return nil
}
