package keeper

type Context struct{}

type MsgUpdateConsensusParams struct {
	Authority string
	Params    ConsensusParams
}

type ConsensusParams struct {
	Block BlockParams
}

type BlockParams struct {
	MaxBytes int64
}

func (p ConsensusParams) Validate() error { return nil }

type Keeper struct{}

func (k Keeper) SetParams(ctx Context, params ConsensusParams) {}

type msgServer struct {
	Keeper
}

func (m msgServer) UpdateConsensusParams(ctx Context, msg *MsgUpdateConsensusParams) error {
	params := msg.Params
	if err := params.Validate(); err != nil {
		return err
	}
	m.Keeper.SetParams(ctx, params)
	return nil
}
