package keeper

import (
	"github.com/cosmos/gogoproto/proto"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// DETERMINISTIC: the concrete type is chosen by a TypeUrl discriminator BEFORE
// decode, so the decode is canonical (no first-nil-wins ambiguity). Must stay
// SILENT (the _G5_DISCRIMINATOR precision guard).
func (k Keeper) StoreCanonical(ctx sdk.Context, bz []byte, payload Any) {
	var a TypeA
	var b TypeB
	switch payload.TypeUrl {
	case "a":
		if proto.Unmarshal(bz, &a) == nil {
			k.SetRecord(ctx, a)
		}
	case "b":
		if proto.Unmarshal(bz, &b) == nil {
			k.SetRecord(ctx, b)
		}
	}
}
