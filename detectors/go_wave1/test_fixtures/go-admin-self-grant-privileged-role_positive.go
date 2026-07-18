// fixture: positive - public admin setter self-grants the caller.
package keeper

type Keeper struct {
	admin string
}

type Context struct{}

type MsgGrantAdmin struct {
	Caller string
}

func (k Keeper) GrantAdmin(ctx Context, msg *MsgGrantAdmin) error {
	_ = ctx
	k.admin = msg.Caller
	return nil
}
