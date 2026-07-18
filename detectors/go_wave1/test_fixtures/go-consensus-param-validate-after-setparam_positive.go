// fixture: positive - consensus param validation is late or only partial.
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

// ApplyConsensusParamsLateValidate commits first and validates afterward.
func (k Keeper) ApplyConsensusParamsLateValidate(ctx Context, params ConsensusParams) error {
	k.store.Set(ctx, params)
	return ValidateConsensusParams(params)
}

// UpdateConsensusParamsPartialValidate checks one local field, then commits
// the whole params object without whole-object validation.
func (k Keeper) UpdateConsensusParamsPartialValidate(ctx Context, params ConsensusParams) error {
	if err := ValidateMaxBytes(params.Block.MaxBytes); err != nil {
		return err
	}
	k.SetParams(ctx, params)
	return nil
}

// ApplyConsensusParamsInlineFieldGuard checks one field, then commits the
// whole object with other consensus fields unvalidated.
func (k Keeper) ApplyConsensusParamsInlineFieldGuard(ctx Context, params ConsensusParams) error {
	if params.VoteExtensionsEnableHeight < 0 {
		return errInvalidVoteExtensionHeight
	}
	k.store.Set(ctx, params)
	return nil
}

var errInvalidVoteExtensionHeight = validationError("bad vote extension height")

type validationError string

func (e validationError) Error() string {
	return string(e)
}
