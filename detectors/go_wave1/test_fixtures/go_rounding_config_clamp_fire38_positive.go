// fixture: positive - config clamp inputs are rounded or overflowed first.
package keeper

import "errors"

const (
	BpsDenom      uint64 = 10_000
	MaxPriceScale uint32 = 1_000_000
)

type ClampConfig struct {
	ProtocolFeeBps uint64
	MaxFee         uint64
	MinNetFee      uint64
	MaxDiscount    uint64
	PriceScale     uint64
	ScaleMultiplier uint64
	MaintenanceBps uint64
	MinCollateral  uint64
}

type ClampState struct {
	ProtocolRevenue uint64
	Discounts       map[string]uint64
	PriceScale      uint32
	RequiredMargin  uint64
}

type Position struct {
	User       string
	Notional   uint64
	Collateral uint64
}

// ChargeClampedProtocolFee can overflow or round before max fee enforcement.
func ChargeClampedProtocolFee(state *ClampState, cfg ClampConfig, notional uint64) {
	fee := notional * cfg.ProtocolFeeBps / BpsDenom
	if fee > cfg.MaxFee {
		fee = cfg.MaxFee
	}
	state.ProtocolRevenue += fee
}

// RecordDiscount underflows before the result is clamped to MaxDiscount.
func RecordDiscount(state *ClampState, cfg ClampConfig, user string, paid uint64) {
	discount := paid - cfg.MinNetFee
	if discount > cfg.MaxDiscount {
		discount = cfg.MaxDiscount
	}
	state.Discounts[user] = discount
}

// ApplyPriceScaleValidation converts the overflowing product before checking MaxPriceScale.
func ApplyPriceScaleValidation(state *ClampState, cfg ClampConfig) error {
	scale := uint32(cfg.PriceScale * cfg.ScaleMultiplier)
	if scale > MaxPriceScale {
		return errors.New("price scale too high")
	}
	state.PriceScale = scale
	return nil
}

// RequiredMargin floors the maintenance requirement before applying the minimum.
func RequiredMargin(state *ClampState, cfg ClampConfig, pos Position) {
	requiredMargin := pos.Notional * cfg.MaintenanceBps / BpsDenom
	if requiredMargin < cfg.MinCollateral {
		requiredMargin = cfg.MinCollateral
	}
	state.RequiredMargin = requiredMargin
}
