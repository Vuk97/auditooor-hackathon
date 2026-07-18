package positive

// Positive fixture: classic cosmos-sdk-style FreeInfiniteGasDecorator.
// The gating predicate combines isClobMsg() + IsSingleAppInjectedMsg() —
// broad scope. Detector should flag at HIGH and emit msg-type tokens
// recognized from the predicate.

type Ctx struct{ gasMeter int }
type Tx interface{ GetMsgs() []interface{} }

func (c Ctx) WithGasMeter(meter int) Ctx { c.gasMeter = meter; return c }

func NewFreeInfiniteGasMeter() int { return 999 }

func isClobMsg(msgs []interface{}) bool             { return false }
func IsSingleAppInjectedMsg(msgs []interface{}) bool { return false }

type FreeInfiniteGasDecorator struct{}

func (dec FreeInfiniteGasDecorator) AnteHandle(ctx Ctx, tx Tx, simulate bool) (Ctx, error) {
	hasClobMsg := isClobMsg(tx.GetMsgs())
	if hasClobMsg || IsSingleAppInjectedMsg(tx.GetMsgs()) {
		ctx = ctx.WithGasMeter(NewFreeInfiniteGasMeter())
	}
	return ctx, nil
}

type SecondDecorator struct{}

func (d SecondDecorator) AnteHandle(ctx Ctx, tx Tx) (Ctx, error) {
	// Second free-gas path — narrower predicate (only MsgPlaceOrder)
	if isClobMsg(tx.GetMsgs()) {
		ctx = ctx.WithGasMeter(NewFreeInfiniteGasMeter())
	}
	return ctx, nil
}
