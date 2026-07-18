// fixture: negative - caller is checked and the new admin is distinct.
package keeper

type Keeper struct {
	admin string
}

type Context struct{}

type MsgGrantAdmin struct {
	Caller   string
	NewAdmin string
}

func (k Keeper) GrantAdmin(ctx Context, msg *MsgGrantAdmin) error {
	_ = ctx
	if msg.Caller != k.admin {
		return errUnauthorized
	}
	if msg.NewAdmin == msg.Caller {
		return errSelfProposal
	}
	k.admin = msg.NewAdmin
	return nil
}

var (
	errUnauthorized = errorString("unauthorized")
	errSelfProposal  = errorString("self proposal")
)

type errorString string

func (e errorString) Error() string { return string(e) }
