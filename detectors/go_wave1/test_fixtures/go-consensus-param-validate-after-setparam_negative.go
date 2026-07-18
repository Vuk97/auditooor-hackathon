// fixture: negative - whole consensus params are validated before writes.
package keeper

type Context struct{}

type Keeper struct {
	store ParamStore
}

type ParamStore struct{}

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

func (ParamStore) Set(ctx Context, params ConsensusParams) {
	_ = ctx
	_ = params
}

func (k Keeper) SetParams(ctx Context, params ConsensusParams) {
	_ = ctx
	_ = params
}

func ValidateConsensusParams(params ConsensusParams) error {
	_ = params
	return nil
}

func ValidateMaxBytes(maxBytes int64) error {
	_ = maxBytes
	return nil
}

// ApplyConsensusParamsWholeValidate validates the candidate before writing.
func (k Keeper) ApplyConsensusParamsWholeValidate(ctx Context, params ConsensusParams) error {
	if err := ValidateConsensusParams(params); err != nil {
		return err
	}
	k.store.Set(ctx, params)
	return nil
}

// UpdateConsensusParamsPartialThenWhole is safe because the partial check is
// followed by whole-object validation before the write.
func (k Keeper) UpdateConsensusParamsPartialThenWhole(ctx Context, params ConsensusParams) error {
	if err := ValidateMaxBytes(params.Block.MaxBytes); err != nil {
		return err
	}
	if err := ValidateConsensusParams(params); err != nil {
		return err
	}
	k.SetParams(ctx, params)
	return nil
}

type RewardParams struct {
	Rate int64
}

// ApplyRewardParams validates unrelated reward params and writes non-consensus
// state. It should not trigger this consensus-param detector.
func (k Keeper) ApplyRewardParams(ctx Context, params RewardParams) error {
	if params.Rate < 0 {
		return errInvalidRewardRate
	}
	return nil
}

var errInvalidRewardRate = validationError("bad reward rate")

type validationError string

func (e validationError) Error() string {
	return string(e)
}
