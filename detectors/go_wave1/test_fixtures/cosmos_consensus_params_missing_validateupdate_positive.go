// fixture: positive - consensus params are overwritten without validation.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct{}

type ConsensusParams struct {
	BlockMaxBytes uint64
}

// UpdateConsensusParams writes the new consensus params directly.
func (k Keeper) UpdateConsensusParams(ctx sdk.Context, params ConsensusParams) error {
	k.SetConsensusParams(ctx, params)
	_ = ctx.WithConsensusParams(params)
	return nil
}

func (k Keeper) SetConsensusParams(ctx sdk.Context, params ConsensusParams) {
	_ = ctx
	_ = params
}

type MsgUpdateParams struct {
	Params Params
}

type Params struct {
	VoteExtensionsEnableHeight int64
}

type MsgUpdateParamsResponse struct{}

// UpdateParams writes a consensus-shaped params payload through the generic
// Cosmos MsgUpdateParams path without a validation call first.
func (k Keeper) UpdateParams(ctx sdk.Context, msg *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	params := msg.Params
	_ = params.VoteExtensionsEnableHeight
	k.SetParams(ctx, params)
	return &MsgUpdateParamsResponse{}, nil
}

func (k Keeper) SetParams(ctx sdk.Context, params Params) {
	_ = ctx
	_ = params
}

type App struct {
	ConsensusParamsKeeper ConsensusParamsKeeper
}

type ConsensusParamsKeeper struct {
	ParamsStore ParamsStore
}

type ParamsStore struct{}

type BlockParams struct {
	MaxBytes int64
}

type AppConsensusParams struct {
	Block BlockParams
}

// ApplyConsensusParams persists a Block.MaxBytes mutation before validating.
func (app App) ApplyConsensusParams(ctx sdk.Context, params AppConsensusParams) error {
	params.Block.MaxBytes = -1
	app.ConsensusParamsKeeper.ParamsStore.Set(ctx, params)
	return params.Validate()
}

func (ParamsStore) Set(ctx sdk.Context, params AppConsensusParams) {
	_ = ctx
	_ = params
}

func (params AppConsensusParams) Validate() error {
	_ = params
	return nil
}
