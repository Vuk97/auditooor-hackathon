package keeper

type Context struct{}

type SubaccountID struct {
	Owner string
}

type BankKeeper struct{}

type Keeper struct {
	bankKeeper BankKeeper
}

type msgServer struct {
	keeper Keeper
}

type WithdrawFromSubaccountMsg struct {
	SubaccountId SubaccountID
}

func (BankKeeper) SendCoins(Context, SubaccountID) error { return nil }

func (k Keeper) CheckValidSubaccount(ctx Context, id SubaccountID) error { return nil }

func (k msgServer) WithdrawFromSubaccount(ctx Context, msg WithdrawFromSubaccountMsg) error {
	if err := k.keeper.CheckValidSubaccount(ctx, msg.SubaccountId); err != nil {
		return err
	}
	return k.keeper.bankKeeper.SendCoins(ctx, msg.SubaccountId)
}
