// fixture: negative — credit paths check the blocked-address registry.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// distributes rewards only after the blocked-addr check.
func (k Keeper) DistributeReward(ctx sdk.Context, recipient sdk.AccAddress, amt sdk.Coins) error {
	if k.bankKeeper.BlockedAddr(recipient) {
		return ErrBlockedAddress
	}
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "rewards", recipient, amt)
}

// airdrop checks the freeze registry first.
func (k Keeper) Airdrop(ctx sdk.Context, to sdk.AccAddress, amt sdk.Coins) error {
	if k.IsFrozen(ctx, to) {
		return ErrAddressFrozen
	}
	return k.bankKeeper.AddCoins(ctx, to, amt)
}

// query-only helper, no credit — must NOT flag.
func (k Keeper) GetReward(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins {
	return k.rewards[addr.String()]
}
