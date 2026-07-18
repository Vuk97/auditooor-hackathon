// fixture: negative - consensus params are validated and authority is checked.
package keeper

type Context struct{}

type msgServer struct {
	Keeper
	authority string
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

var ErrUnauthorized = validationError("unauthorized")

type validationError string

func (e validationError) Error() string {
	return string(e)
}

func (params ConsensusParams) Validate() error {
	_ = params
	return nil
}

func (k Keeper) SetParams(ctx Context, params ConsensusParams) {
	_ = ctx
	_ = params
}

// UpdateParams checks authority before committing caller-supplied consensus
// params, so the detector must not flag it.
func (m msgServer) UpdateParams(ctx Context, msg *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	if msg.Authority != m.authority {
		return nil, ErrUnauthorized
	}
	if err := msg.Params.Validate(); err != nil {
		return nil, err
	}
	m.Keeper.SetParams(ctx, msg.Params)
	return &MsgUpdateParamsResponse{}, nil
}
