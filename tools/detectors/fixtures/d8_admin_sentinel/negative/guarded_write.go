package negative

// Negative: msgServer method writes to state but explicitly checks
// msg.Authority against k.authority FIRST. Pattern A should NOT fire.
// Only one method here, so Pattern B does NOT fire either.
type msgServer struct {
	k *Keeper
}

type Keeper struct {
	authority string
}

type Ctx struct {
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

func (k *Keeper) SetParams(ctx Ctx, p Params) {
	k.authority = "x"
}

func (ms msgServer) UpdateParams(ctx Ctx, msg *MsgSetParams) (*MsgSetParamsResponse, error) {
	if msg.Authority != ms.k.authority {
		return nil, nil
	}
	ms.k.SetParams(ctx, msg.Params)
	return &MsgSetParamsResponse{}, nil
}
