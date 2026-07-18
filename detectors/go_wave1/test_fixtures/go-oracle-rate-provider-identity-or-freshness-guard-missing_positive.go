// fixture: positive - provider identity and freshness/deviation guards missing.
package keeper

type Context struct{}

type OracleClient interface {
	GetPrice(Context, string, string) (int64, int64, error)
	GetEMAPrice(Context, string) (int64, error)
}

type RateProvider interface {
	QueryExchangeRate(Context, string, string, string) (int64, error)
	GetPrimaryRate(Context, string, string) (int64, int64, error)
}

type Keeper struct {
	oracle       OracleClient
	rateProvider RateProvider
}

type MsgLiquidate struct {
	Provider   string
	Asset      string
	Collateral int64
	Debt       int64
}

// BUG: caller chooses provider and the returned price goes straight into
// liquidation math without allowlist, freshness, or deviation checks.
func (k Keeper) LiquidateWithUserProvider(ctx Context, msg MsgLiquidate) bool {
	price, updatedAt, err := k.oracle.GetPrice(ctx, msg.Provider, msg.Asset)
	if err != nil {
		return false
	}
	_ = updatedAt
	collateralValue := msg.Collateral * price / 1_000_000
	return collateralValue < msg.Debt
}

// BUG: provider-selected exchange rate feeds accounting directly with no
// allowlist or stale/deviation check.
func (k Keeper) AccountValueFromUnboundedRate(ctx Context, providerID string, shares int64, debt int64) int64 {
	rate, err := k.rateProvider.QueryExchangeRate(ctx, providerID, "stETH", "ETH")
	if err != nil {
		return 0
	}
	accountValue := shares * rate / 1_000_000
	if accountValue < debt {
		return debt - accountValue
	}
	return accountValue - debt
}

// BUG: a built-in primary rate is still stale-sensitive if the returned
// timestamp and deviation are never checked before accounting uses it.
func (k Keeper) ComputeMarginFromStalePrimaryRate(ctx Context, notional int64, liability int64) int64 {
	rate, updatedAt, err := k.rateProvider.GetPrimaryRate(ctx, "ATOM", "USD")
	if err != nil {
		return 0
	}
	_ = updatedAt
	marginValue := notional * rate / 1_000_000
	if marginValue < liability {
		return liability - marginValue
	}
	return marginValue - liability
}

// BUG: EMA price is used as the only liquidation input, with no freshness or
// spot/deviation cross-check.
func (k Keeper) IsLiquidatableOnEmaOnly(ctx Context, provider string, collateral int64, debt int64) bool {
	emaPrice, err := k.oracle.GetEMAPrice(ctx, provider)
	if err != nil {
		return false
	}
	return collateral*emaPrice/1_000_000 < debt
}
