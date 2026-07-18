// fixture: negative - provider identity and freshness/deviation are checked.
package keeper

import "time"

type Context struct{}

type OracleClient interface {
	GetPrice(Context, string, string) (int64, int64, error)
	GetSpotPrice(Context, string) (int64, error)
	GetEMAPriceWithTimestamp(Context, string) (int64, int64, error)
}

type RateProvider interface {
	QueryExchangeRateWithTimestamp(Context, string, string, string) (int64, int64, error)
	QueryReferenceRate(Context, string, string) (int64, error)
	GetPrimaryRate(Context, string, string) (int64, int64, error)
}

type Keeper struct {
	oracle           OracleClient
	rateProvider     RateProvider
	allowedProviders map[string]bool
}

type MsgLiquidate struct {
	Provider   string
	Asset      string
	Collateral int64
	Debt       int64
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func (k Keeper) LiquidateWithAllowlistedFreshPrice(ctx Context, msg MsgLiquidate) bool {
	if !k.allowedProviders[msg.Provider] {
		return false
	}
	price, updatedAt, err := k.oracle.GetPrice(ctx, msg.Provider, msg.Asset)
	if err != nil {
		return false
	}
	if time.Now().Unix()-updatedAt > 60 {
		return false
	}
	spotPrice, err := k.oracle.GetSpotPrice(ctx, msg.Asset)
	if err != nil {
		return false
	}
	diff := abs64(price - spotPrice)
	if diff*10_000 > spotPrice*500 {
		return false
	}
	collateralValue := msg.Collateral * price / 1_000_000
	return collateralValue < msg.Debt
}

func (k Keeper) AccountValueFromAllowedRateProvider(ctx Context, providerID string, shares int64, debt int64) int64 {
	if !k.allowedProviders[providerID] {
		return 0
	}
	rate, updatedAt, err := k.rateProvider.QueryExchangeRateWithTimestamp(ctx, providerID, "stETH", "ETH")
	if err != nil {
		return 0
	}
	if time.Now().Unix()-updatedAt > 60 {
		return 0
	}
	referenceRate, err := k.rateProvider.QueryReferenceRate(ctx, "stETH", "ETH")
	if err != nil {
		return 0
	}
	diff := abs64(rate - referenceRate)
	if diff*10_000 > referenceRate*300 {
		return 0
	}
	accountValue := shares * rate / 1_000_000
	if accountValue < debt {
		return debt - accountValue
	}
	return accountValue - debt
}

func (k Keeper) ComputeMarginFromFreshPrimaryRate(ctx Context, notional int64, liability int64) int64 {
	rate, updatedAt, err := k.rateProvider.GetPrimaryRate(ctx, "ATOM", "USD")
	if err != nil {
		return 0
	}
	if time.Now().Unix()-updatedAt > 60 {
		return 0
	}
	referenceRate, err := k.rateProvider.QueryReferenceRate(ctx, "ATOM", "USD")
	if err != nil {
		return 0
	}
	diff := abs64(rate - referenceRate)
	if diff*10_000 > referenceRate*300 {
		return 0
	}
	marginValue := notional * rate / 1_000_000
	if marginValue < liability {
		return liability - marginValue
	}
	return marginValue - liability
}

func (k Keeper) IsLiquidatableOnGuardedEma(ctx Context, provider string, collateral int64, debt int64) bool {
	if !k.allowedProviders[provider] {
		return false
	}
	emaPrice, updatedAt, err := k.oracle.GetEMAPriceWithTimestamp(ctx, provider)
	if err != nil {
		return false
	}
	if time.Now().Unix()-updatedAt > 60 {
		return false
	}
	spotPrice, err := k.oracle.GetSpotPrice(ctx, provider)
	if err != nil {
		return false
	}
	diff := abs64(emaPrice - spotPrice)
	if diff*10_000 > spotPrice*250 {
		return false
	}
	return collateral*emaPrice/1_000_000 < debt
}
