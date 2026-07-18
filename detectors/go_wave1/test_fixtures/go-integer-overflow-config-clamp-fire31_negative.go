// fixture: negative - config values are checked before narrowing.
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
	DebugBucket   uint64
}

// ApplyMaxOrdersConfigChecked rejects the wide config value before casting.
func ApplyMaxOrdersConfigChecked(state *MarketState, cfg MarketConfig) error {
	if cfg.MaxOrders > uint64(MaxMarketOrders) {
		return errors.New("too many orders")
	}
	maxOrders := uint32(cfg.MaxOrders)
	state.MaxOrders = uint64(maxOrders)
	return nil
}

// ApplyOraclePriceScaleChecked rejects overflow and policy bounds before cast.
func ApplyOraclePriceScaleChecked(state *MarketState, cfg MarketConfig) error {
	if cfg.PriceScale == 0 || cfg.PriceScale > uint64(MaxPriceScale) {
		return errors.New("bad price scale")
	}
	priceScale := uint16(cfg.PriceScale)
	state.PriceScale = uint64(priceScale)
	return nil
}

// BuildRiskThresholdChecked checks the wide source before using uint16.
func BuildRiskThresholdChecked(cfg MarketConfig) (MarketState, error) {
	if cfg.RiskFactorBps > uint64(MaxRiskBps) {
		return MarketState{}, errors.New("bad risk factor")
	}
	riskFactor := uint16(cfg.RiskFactorBps)
	return MarketState{RiskFactorBps: uint64(riskFactor)}, nil
}

// StoreDebugBucket narrows a non-config loop bucket and writes debug state only.
func StoreDebugBucket(state *MarketState, index uint64) error {
	bucket := uint32(index)
	if bucket > 1_000 {
		return errors.New("debug bucket too large")
	}
	state.DebugBucket = uint64(bucket)
	return nil
}
