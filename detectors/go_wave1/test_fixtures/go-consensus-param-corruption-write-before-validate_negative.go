// fixture: negative - consensus params are validated before the first write.
package keeper

type Context struct{}

type Keeper struct{}

type ConsensusParams struct {
	VoteExtensionsEnableHeight int64
}

type ParamsStore struct{}

type ConsensusParamsKeeper struct {
	ParamsStore ParamsStore
}

type App struct {
	ConsensusParamsKeeper ConsensusParamsKeeper
}

type BlockParams struct {
	MaxBytes int64
}

type AppConsensusParams struct {
	Block BlockParams
}

func (ParamsStore) Set(ctx Context, params AppConsensusParams) {
	_ = ctx
	_ = params
}

func (k Keeper) SetConsensusParams(ctx Context, params ConsensusParams) {
	_ = ctx
	_ = params
}

// ApplyConsensusParams validates before persisting.
func (app App) ApplyConsensusParams(ctx Context, params AppConsensusParams) error {
	if err := params.Validate(); err != nil {
		return err
	}
	app.ConsensusParamsKeeper.ParamsStore.Set(ctx, params)
	return nil
}

func (params AppConsensusParams) Validate() error {
	_ = params
	return nil
}

// UpdateConsensusParams validates before the write sink.
func (k Keeper) UpdateConsensusParams(ctx Context, params ConsensusParams) error {
	if err := params.Validate(); err != nil {
		return err
	}
	_ = params.VoteExtensionsEnableHeight
	k.SetConsensusParams(ctx, params)
	return nil
}

func (params ConsensusParams) Validate() error {
	return nil
}
