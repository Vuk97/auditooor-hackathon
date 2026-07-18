// fixture: positive - consensus params are written before validation.
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

// ApplyConsensusParams persists the candidate params before validation.
func (app App) ApplyConsensusParams(ctx Context, params AppConsensusParams) error {
	app.ConsensusParamsKeeper.ParamsStore.Set(ctx, params)
	return params.Validate()
}

func (params AppConsensusParams) Validate() error {
	_ = params
	return nil
}

// UpdateConsensusParams writes consensus params directly with no validation.
func (k Keeper) UpdateConsensusParams(ctx Context, params ConsensusParams) error {
	_ = params.VoteExtensionsEnableHeight
	k.SetConsensusParams(ctx, params)
	return nil
}
