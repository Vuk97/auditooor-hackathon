package fixtures

type Context struct{}
type Coins struct{}
type AccAddress string

type MsgClaim struct {
	Id        uint64
	Recipient AccAddress
	Amount    Coins
}

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(Context, string, AccAddress, Coins) error {
	return nil
}

type Keeper struct {
	bankKeeper BankKeeper
	processed  map[uint64]bool
}

func (k Keeper) ProcessClaim(ctx Context, msg MsgClaim) error {
	k.processed[msg.Id] = true
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "claims", msg.Recipient, msg.Amount)
}
