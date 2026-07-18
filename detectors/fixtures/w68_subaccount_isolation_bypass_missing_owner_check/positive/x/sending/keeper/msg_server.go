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

func (k Keeper) MustGetSubaccount(ctx Context, id SubaccountID) SubaccountID {
	return id
}

func (k msgServer) WithdrawFromSubaccount(ctx Context, msg WithdrawFromSubaccountMsg) error {
	sub := k.keeper.MustGetSubaccount(ctx, msg.SubaccountId)
	return k.keeper.bankKeeper.SendCoins(ctx, sub)
}
