// fixture: positive - consensus params are validated but authority is missing.
package keeper

type Context struct{}

type msgServer struct {
	Keeper
}

type Keeper struct{}

type MsgUpdateParams struct {
	Authority string
	Params    ConsensusParams
}

type MsgUpdateParamsResponse struct{}

type ConsensusParams struct {
	Block                      BlockParams
	Evidence                   EvidenceParams
	VoteExtensionsEnableHeight int64
}

type BlockParams struct {
	MaxBytes int64
	MaxGas   int64
}

type EvidenceParams struct {
	MaxAgeNumBlocks int64
}

func (params ConsensusParams) Validate() error {
	_ = params
	return nil
}

func (k Keeper) SetParams(ctx Context, params ConsensusParams) {
	_ = ctx
	_ = params
}

// UpdateParams validates the consensus payload but never proves that
// msg.Authority is the module authority before committing the params.
func (m msgServer) UpdateParams(ctx Context, msg *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	params := msg.Params
	if err := params.Validate(); err != nil {
		return nil, err
	}
	m.Keeper.SetParams(ctx, params)
	return &MsgUpdateParamsResponse{}, nil
}
