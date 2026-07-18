// Positive fixture for go.cosmos.subaccount_filter_mismatch (Pattern 44).
// The functions below use SubaccountId as a filter key but then read a balance
// via bankKeeper.GetBalance against the module address, NOT the per-subaccount
// address -- the canonical bug shape.
package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// GetSubaccountCollateral reads a subaccount selector then queries the module
// balance without deriving the subaccount address -- stale isolation bug.
func GetSubaccountCollateral(ctx context.Context, subaccountId uint32) (sdk.Coin, error) {
	// Filter by subaccount ...
	sub := k.GetSubaccountId(ctx, subaccountId)
	if sub == nil {
		return sdk.Coin{}, ErrNotFound
	}
	// BAD: reads module-level balance, not per-subaccount balance.
	balance := bankKeeper.GetBalance(ctx, moduleAddr, "USDC")
	return balance, nil
}

// ValidateSubaccountMargin checks margin but queries wrong address.
func ValidateSubaccountMargin(ctx context.Context, subaccountId uint32) bool {
	_ = GetSubaccount(ctx, subaccountId)
	// BAD: does not derive per-subaccount address.
	coins := GetBalance(ctx, communityPoolAddr)
	return coins.Amount.GT(sdk.ZeroInt())
}
