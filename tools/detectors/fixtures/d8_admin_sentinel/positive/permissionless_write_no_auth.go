package positive

// Pattern A positive: msgServer method writes to KVStore without any
// authority check before the mutation. Anyone can call SetParams here.
type msgServer struct {
	k *Keeper
}

type Keeper struct {
	dummy int
}

type Context struct {
	dummy int
}

type Params struct {
	Foo string
}

type MsgSetParams struct {
	Authority string
	Params    Params
}

type MsgSetParamsResponse struct {
	dummy int
}

func (k *Keeper) SetParams(ctx Context, p Params) {
	k.dummy = 1
}

// SetParams is a permissionless write — no authority gate.
func (ms msgServer) SetParams(ctx Context, msg *MsgSetParams) (*MsgSetParamsResponse, error) {
	// No ms.k.authority check, no msg.Authority comparison — anyone wins.
	ms.k.SetParams(ctx, msg.Params)
	return &MsgSetParamsResponse{}, nil
}
