// fixture: negative — every fallible getter result is guarded before use.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// found bool is checked before dereference.
func (k Keeper) ProcessMarket(ctx sdk.Context, id uint32) error {
	market, found := k.GetMarket(ctx, id)
	if !found {
		return ErrMarketNotFound
	}
	k.applyTick(ctx, market.OraclePrice, market.Pair)
	return nil
}

// pointer getter with explicit nil guard.
func (k Keeper) SettlePerp(ctx sdk.Context, id uint32) error {
	perp := k.GetPerpetual(ctx, id)
	if perp == nil {
		return ErrPerpetualNotFound
	}
	return k.settle(ctx, perp.QuoteBalance)
}

// found used directly in the if condition.
func (k Keeper) ReadOracle(ctx sdk.Context, pair string) (sdk.Dec, error) {
	price, found := k.LookupOraclePrice(ctx, pair)
	if !found {
		return sdk.ZeroDec(), ErrOracleStale
	}
	return price.Value, nil
}
