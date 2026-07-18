// fixture: negative - consensus params are validated before overwrite.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct{}

type ConsensusParams struct {
	BlockMaxBytes uint64
}

// UpdateConsensusParams validates before writing the new consensus params.
func (k Keeper) UpdateConsensusParams(ctx sdk.Context, params ConsensusParams) error {
	if err := params.Validate(); err != nil {
		return err
	}
	k.SetConsensusParams(ctx, params)
	_ = ctx.WithConsensusParams(params)
	return nil
}

func (params ConsensusParams) Validate() error {
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

// UpdateParams validates a consensus-shaped generic params payload before
// writing through the generic Cosmos MsgUpdateParams path.
func (k Keeper) UpdateParams(ctx sdk.Context, msg *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	params := msg.Params
	if err := ValidateUpdate(ctx, params); err != nil {
		return nil, err
	}
	_ = params.VoteExtensionsEnableHeight
	k.SetParams(ctx, params)
	return &MsgUpdateParamsResponse{}, nil
}

func ValidateUpdate(ctx sdk.Context, params Params) error {
	_ = ctx
	_ = params
	return nil
}

func (k Keeper) SetParams(ctx sdk.Context, params Params) {
	_ = ctx
	_ = params
}

type RewardParams struct {
	Rate int64
}

// SetParams on non-consensus params should not be enough to trigger.
func (k Keeper) UpdateRewardParams(ctx sdk.Context, params RewardParams) error {
	k.SetRewardParams(ctx, params)
	return nil
}

func (k Keeper) SetRewardParams(ctx sdk.Context, params RewardParams) {
	_ = ctx
	_ = params
}
