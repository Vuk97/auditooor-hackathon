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

// ProcessClaim sends payout first and only then marks the claim consumed.
func (k Keeper) ProcessClaim(ctx Context, msg MsgClaim) error {
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "claims", msg.Recipient, msg.Amount); err != nil {
		return err
	}
	k.processed[msg.Id] = true
	return nil
}
