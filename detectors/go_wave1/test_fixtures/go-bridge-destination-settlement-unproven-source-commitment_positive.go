package bridge

type Context struct{}
type Address string
type Coins int64

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(ctx Context, module string, recipient Address, amount Coins) error {
	return nil
}

type Keeper struct {
	processedTransfers map[string]bool
	bankKeeper         BankKeeper
}

func (k Keeper) CompleteBridgeTransfer(ctx Context, recipient Address, amount Coins, transferId string) error {
	if k.processedTransfers[transferId] {
		return nil
	}

	k.processedTransfers[transferId] = true
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", recipient, amount)
}
