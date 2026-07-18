// Negative fixture for go.cosmos.subaccount_filter_mismatch (Pattern 44).
// The function uses SubaccountId but ALSO derives the per-subaccount address
// before calling GetBalance -- pattern must NOT fire.
package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// GetSubaccountCollateralSafe properly derives the subaccount address first.
func GetSubaccountCollateralSafe(ctx context.Context, subaccountId uint32) (sdk.Coin, error) {
	sub := k.GetSubaccountId(ctx, subaccountId)
	if sub == nil {
		return sdk.Coin{}, ErrNotFound
	}
	// SAFE: derives the per-subaccount address before the balance read.
	subAddr := SubaccountIdToAddress(subaccountId)
	balance := bankKeeper.GetBalance(ctx, subAddr, "USDC")
	return balance, nil
}

// GetModuleBalanceNoSubaccount reads module balance without any subaccount filter.
// No SubaccountId reference at all -- must NOT fire.
func GetModuleBalanceNoSubaccount(ctx context.Context) sdk.Coin {
	return bankKeeper.GetBalance(ctx, moduleAddr, "USDC")
}
