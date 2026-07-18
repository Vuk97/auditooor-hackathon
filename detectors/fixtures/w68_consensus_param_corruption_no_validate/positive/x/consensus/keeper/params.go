package keeper

type Context struct{}

type ConsensusParams struct{}

type Keeper struct{}

func (k Keeper) UpdateConsensusParams(ctx Context, params ConsensusParams) error {
	k.SetConsensusParams(ctx, params)
	return nil
}

func (k Keeper) SetConsensusParams(ctx Context, params ConsensusParams) {}
