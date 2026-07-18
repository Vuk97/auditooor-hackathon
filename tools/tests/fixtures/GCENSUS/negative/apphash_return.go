package keeper

import (
	"context"
	"time"
)

// NEGATIVE (precision fix a): `AppHash` here is a RETURN value, NOT a write-LHS.
// It fired only because the census sink universe once carried a bare
// `\bAppHash\b` token AND time.Now co-occurs in the window (flowing into the
// verification call, not the returned value). A return is not a consensus write
// -> must stay SILENT.
func (k Keeper) AppHashAt(ctx context.Context, height uint64) ([]byte, error) {
	header, err := k.verify(ctx, height, time.Now())
	if err != nil {
		return nil, err
	}
	return header.AppHash, nil
}
