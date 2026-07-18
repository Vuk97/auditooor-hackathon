// fixture: positive — InitGenesis consumes genesis without validation.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis writes params and markets straight from genState, no Validate.
func (k Keeper) InitGenesis(ctx sdk.Context, genState GenesisState) {
	k.SetParams(ctx, genState.Params)
	for _, m := range genState.Markets {
		k.SetMarket(ctx, m)
	}
}

// module-qualified InitGenesis form, also unvalidated.
func InitGenesis(ctx sdk.Context, k Keeper, data GenesisState) {
	k.SetParams(ctx, data.Params)
	store := ctx.KVStore(k.storeKey)
	store.Set([]byte("supply"), data.Supply)
}
