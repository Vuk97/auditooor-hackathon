package fixtures

type Context struct{}
type Coins struct{}
type AccAddress string

type Memo struct {
	Recipient AccAddress
}

type MsgTransferOut struct {
	ToAddress AccAddress
	Amount    Coins
}

type Dispatcher struct{}

func (Dispatcher) Dispatch(Context, AccAddress, Coins, AccAddress) error {
	return nil
}

type Keeper struct {
	dispatcher Dispatcher
}

func (k Keeper) RouteTransfer(ctx Context, msg MsgTransferOut, memo Memo) error {
	return k.dispatcher.Dispatch(ctx, memo.Recipient, msg.Amount, msg.ToAddress)
}
