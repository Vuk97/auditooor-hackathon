// fixture: negative - clamp inputs are checked before lossy integer math.
package keeper

import (
	"errors"
	"math"
)

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
	DebugBucket     uint64
}

type Position struct {
	User       string
	Notional   uint64
	Collateral uint64
}

// ChargeClampedProtocolFeeChecked rejects overflow and non-exact rounding first.
func ChargeClampedProtocolFeeChecked(state *ClampState, cfg ClampConfig, notional uint64) error {
	if cfg.ProtocolFeeBps != 0 && notional > math.MaxUint64/cfg.ProtocolFeeBps {
		return errors.New("fee overflow")
	}
	if (notional*cfg.ProtocolFeeBps)%BpsDenom != 0 {
		return errors.New("fee would round")
	}
	fee := notional * cfg.ProtocolFeeBps / BpsDenom
	if fee > cfg.MaxFee {
		fee = cfg.MaxFee
	}
	state.ProtocolRevenue += fee
	return nil
}

// RecordDiscountChecked rejects the unsigned underflow before subtraction.
func RecordDiscountChecked(state *ClampState, cfg ClampConfig, user string, paid uint64) error {
	if paid < cfg.MinNetFee {
		return errors.New("below minimum net fee")
	}
	discount := paid - cfg.MinNetFee
	if discount > cfg.MaxDiscount {
		discount = cfg.MaxDiscount
	}
	state.Discounts[user] = discount
	return nil
}

// ApplyPriceScaleValidationChecked bounds the wide product before narrowing.
func ApplyPriceScaleValidationChecked(state *ClampState, cfg ClampConfig) error {
	if cfg.PriceScale != 0 && cfg.ScaleMultiplier > uint64(MaxPriceScale)/cfg.PriceScale {
		return errors.New("price scale too high")
	}
	scale := uint32(cfg.PriceScale * cfg.ScaleMultiplier)
	if scale > MaxPriceScale {
		return errors.New("price scale too high")
	}
	state.PriceScale = scale
	return nil
}

// RequiredMarginChecked rejects non-exact rounding before applying a minimum.
func RequiredMarginChecked(state *ClampState, cfg ClampConfig, pos Position) error {
	if (pos.Notional*cfg.MaintenanceBps)%BpsDenom != 0 {
		return errors.New("maintenance would round")
	}
	requiredMargin := pos.Notional * cfg.MaintenanceBps / BpsDenom
	if requiredMargin < cfg.MinCollateral {
		requiredMargin = cfg.MinCollateral
	}
	state.RequiredMargin = requiredMargin
	return nil
}

// StoreDebugBucket clamps non-config debug sampling math only.
func StoreDebugBucket(state *ClampState, samples uint64, interval uint64) {
	bucket := samples * interval / 10
	if bucket > 1_000 {
		bucket = 1_000
	}
	state.DebugBucket = bucket
}
