package fixtures

type Context struct{}

type TxState struct {
	FeeRate uint64
	BaseFee uint64
}

type Keeper struct{}

func (Keeper) RefreshFeeRate(Context, *TxState) {}

func (Keeper) BuildBackupTx(Context, *TxState, uint64) uint64 { return 0 }

func (k Keeper) BuildBackupTransaction(ctx Context, state *TxState) uint64 {
	feeRate := state.FeeRate
	if feeRate == 0 {
		return 0
	}
	k.RefreshFeeRate(ctx, state)
	return k.BuildBackupTx(ctx, state, feeRate)
}
