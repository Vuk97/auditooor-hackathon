package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

type MsgTally struct {
	ExchangeRate sdk.Dec
}

type Keeper struct{}

// TallyExchangeRateSafe guards the attacker divisor with IsPositive() before
// dividing. The zero-guard clears the body. => G2 must NOT fire.
func (k Keeper) TallyExchangeRateSafe(ctx sdk.Context, msg MsgTally, base sdk.Dec) sdk.Dec {
	if msg.ExchangeRate.IsPositive() {
		return base.Quo(msg.ExchangeRate)
	}
	return sdk.ZeroDec()
}
