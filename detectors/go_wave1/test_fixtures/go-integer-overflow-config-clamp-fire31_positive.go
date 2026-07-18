// fixture: positive - config values are narrowed before validation.
package keeper

import "errors"

const (
	MaxMarketOrders uint32 = 1_000_000
	MaxPriceScale   uint16 = 50_000
	MaxRiskBps      uint16 = 10_000
)

type MarketConfig struct {
	MaxOrders     uint64
	PriceScale    uint64
	RiskFactorBps uint64
}

type MarketState struct {
	MaxOrders     uint64
	PriceScale    uint64
	RiskFactorBps uint64
}

// ApplyMaxOrdersConfig validates the wrapped uint32 value, not the raw config.
func ApplyMaxOrdersConfig(state *MarketState, cfg MarketConfig) error {
	maxOrders := uint32(cfg.MaxOrders)
	if maxOrders > MaxMarketOrders {
		return errors.New("too many orders")
	}
	state.MaxOrders = uint64(maxOrders)
	return nil
}

// ApplyOraclePriceScale validates a wrapped uint16 price scale before storage.
func ApplyOraclePriceScale(state *MarketState, cfg MarketConfig) error {
	priceScale := uint16(cfg.PriceScale)
	if priceScale == 0 || priceScale > MaxPriceScale {
		return errors.New("bad price scale")
	}
	state.PriceScale = uint64(priceScale)
	return nil
}

// BuildRiskThreshold clamps a wrapped risk factor instead of rejecting cfg.
func BuildRiskThreshold(cfg MarketConfig) MarketState {
	riskFactor := uint16(cfg.RiskFactorBps)
	if riskFactor > MaxRiskBps {
		riskFactor = MaxRiskBps
	}
	return MarketState{RiskFactorBps: uint64(riskFactor)}
}
