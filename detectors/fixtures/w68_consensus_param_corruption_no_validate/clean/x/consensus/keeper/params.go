package keeper

type Context struct{}

type ConsensusParams struct{}

type Keeper struct{}

func (ConsensusParams) Validate() error { return nil }

func (k Keeper) UpdateConsensusParams(ctx Context, params ConsensusParams) error {
	if err := params.Validate(); err != nil {
		return err
	}
	k.SetConsensusParams(ctx, params)
	return nil
}

func (k Keeper) SetConsensusParams(ctx Context, params ConsensusParams) {}
