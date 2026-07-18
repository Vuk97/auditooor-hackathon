// fixture: positive - multiple validation-before-mutation gaps.
package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

type Keeper struct {
	bankKeeper BankKeeper
	storeKey   []byte
}

type BankKeeper interface {
	SendCoinsFromModuleToAccount(sdk.Context, string, sdk.AccAddress, sdk.Coins) error
}

type GenesisState struct {
	Params  Params
	Markets []Market
}

type Params struct{}
type Market struct{}

func (k Keeper) InitGenesis(ctx sdk.Context, genState GenesisState) {
	k.SetParams(ctx, genState.Params)
	for _, market := range genState.Markets {
		k.SetMarket(ctx, market)
	}
}

func (k Keeper) Payout(ctx sdk.Context, to sdk.AccAddress, amt sdk.Coins) error {
	_ = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "pool", to, amt)
	return nil
}

type Request struct {
	GasPrice uint64
}

func tally(req Request, totalGas uint64) uint64 {
	return totalGas / req.GasPrice
}

func (k Keeper) SetParams(ctx sdk.Context, params Params) {}
func (k Keeper) SetMarket(ctx sdk.Context, market Market) {}
