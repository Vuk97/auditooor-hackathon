package negative

// Negative fixture: standard ante decorator that never swaps the gas
// meter for an infinite one. Detector must NOT fire.

type Ctx struct{ gasMeter int }
type Tx interface{ GetMsgs() []interface{} }

func (c Ctx) WithGasMeter(meter int) Ctx { c.gasMeter = meter; return c }

type StandardAnteDecorator struct{}

func (d StandardAnteDecorator) AnteHandle(ctx Ctx, tx Tx, simulate bool) (Ctx, error) {
	// Just consume gas normally — no free-meter swap, no Infinite token anywhere.
	for range tx.GetMsgs() {
		_ = ctx
	}
	return ctx, nil
}

type FeeDeductDecorator struct{}

func (d FeeDeductDecorator) AnteHandle(ctx Ctx, tx Tx) (Ctx, error) {
	if len(tx.GetMsgs()) > 0 {
		// charge fees normally
		_ = ctx
	}
	return ctx, nil
}
