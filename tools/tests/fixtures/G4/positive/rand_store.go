package keeper

import (
	"math/rand"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// HandlePick picks a winner with unseeded math/rand and writes it to state.
// BUG shape: global math/rand is not consensus-safe; must FIRE (rand arm).
func (k Keeper) HandlePick(ctx sdk.Context, msg MsgPick) {
	winner := rand.Intn(len(msg.Candidates))
	k.SetWinner(ctx, msg.Candidates[winner])
}
