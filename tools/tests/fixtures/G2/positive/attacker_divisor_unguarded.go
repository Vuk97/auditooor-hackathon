package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

type MsgTally struct {
	ExchangeRate sdk.Dec
}

type Keeper struct{}

// TallyExchangeRate divides by an attacker-supplied divisor field
// (msg.ExchangeRate) with NO positivity guard and NO defer/recover. The
// sdk.Context param satisfies the cosmos-context gate. => G2 fires.
func (k Keeper) TallyExchangeRate(ctx sdk.Context, msg MsgTally, base sdk.Dec) sdk.Dec {
	return base.Quo(msg.ExchangeRate)
}
