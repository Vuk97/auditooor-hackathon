// fixture: positive — fallible getters dereferenced without a found/nil check.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// market is read with the found bool discarded, then dereferenced -> panic.
func (k Keeper) ProcessMarket(ctx sdk.Context, id uint32) error {
	market, _ := k.GetMarket(ctx, id)
	k.applyTick(ctx, market.OraclePrice, market.Pair)
	return nil
}

// perp pointer getter, no nil check before field access.
func (k Keeper) SettlePerp(ctx sdk.Context, id uint32) error {
	perp := k.GetPerpetual(ctx, id)
	return k.settle(ctx, perp.QuoteBalance)
}

// found bool is kept but never used as a guard -> still a panic risk.
func (k Keeper) ReadOracle(ctx sdk.Context, pair string) sdk.Dec {
	price, found := k.LookupOraclePrice(ctx, pair)
	_ = found
	return price.Value
}
