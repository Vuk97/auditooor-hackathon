// fixture: negative — InitGenesis validates genesis before consuming it.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis validates first, panics on malformed genesis.
func (k Keeper) InitGenesis(ctx sdk.Context, genState GenesisState) {
	if err := genState.Validate(); err != nil {
		panic(err)
	}
	k.SetParams(ctx, genState.Params)
	for _, m := range genState.Markets {
		k.SetMarket(ctx, m)
	}
}

// module-qualified form with explicit ValidateGenesis call.
func InitGenesis(ctx sdk.Context, k Keeper, data GenesisState) {
	if err := ValidateGenesis(data); err != nil {
		panic(err)
	}
	k.SetParams(ctx, data.Params)
	store := ctx.KVStore(k.storeKey)
	store.Set([]byte("supply"), data.Supply)
}

// ExportGenesis only reads state — must NOT flag.
func (k Keeper) ExportGenesis(ctx sdk.Context) GenesisState {
	return GenesisState{Params: k.GetParams(ctx)}
}
