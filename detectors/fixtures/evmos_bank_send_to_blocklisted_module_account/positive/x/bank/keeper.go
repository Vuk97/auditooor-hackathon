package bank

import (
    sdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct{}

func (k Keeper) MsgSend(ctx sdk.Context, fromAddr sdk.AccAddress, toAddr sdk.AccAddress, amt sdk.Coins) error {
    if err := k.subUnlockedCoins(ctx, fromAddr, amt); err != nil {
        return err
    }
    return k.SendCoins(ctx, fromAddr, toAddr, amt)
}
