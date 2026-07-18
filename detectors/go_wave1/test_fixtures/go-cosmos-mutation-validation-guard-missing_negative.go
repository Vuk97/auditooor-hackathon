// fixture: negative - each mutation path validates before accepting state.
package keeper

import (
	"errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct {
	bankKeeper BankKeeper
}

type BankKeeper interface {
	SendCoinsFromModuleToAccount(sdk.Context, string, sdk.AccAddress, sdk.Coins) error
}

type GenesisState struct {
	Params Params
}

func (g GenesisState) Validate() error { return nil }

type Params struct{}

func (k Keeper) InitGenesis(ctx sdk.Context, genState GenesisState) {
	if err := genState.Validate(); err != nil {
		panic(err)
	}
	k.SetParams(ctx, genState.Params)
}

func (k Keeper) Payout(ctx sdk.Context, to sdk.AccAddress, amt sdk.Coins) error {
	if err := k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "pool", to, amt); err != nil {
		return err
	}
	return nil
}

type Request struct {
	GasPrice uint64
}

func tally(req Request, totalGas uint64) (uint64, error) {
	if req.GasPrice == 0 {
		return 0, errors.New("zero gas price")
	}
	return totalGas / req.GasPrice, nil
}

func (k Keeper) SetParams(ctx sdk.Context, params Params) {}
