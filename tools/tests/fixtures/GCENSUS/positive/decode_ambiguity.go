package keeper

import (
	"github.com/cosmos/gogoproto/proto"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// One buffer is trial-decoded into two rival types under a first-`== nil`-wins
// ladder with NO TypeUrl/version discriminator: a peer that crafts a buffer
// decodable as BOTH types makes validators persist a different record ->
// consensus decode-ambiguity divergence. noncanonical_decode provenance
// (G5 oracle reused).
func (k Keeper) Store(ctx sdk.Context, bz []byte) {
	var a TypeA
	var b TypeB
	if proto.Unmarshal(bz, &a) == nil {
		k.SetRecord(ctx, a)
		return
	}
	if proto.Unmarshal(bz, &b) == nil {
		k.SetRecord(ctx, b)
		return
	}
}
