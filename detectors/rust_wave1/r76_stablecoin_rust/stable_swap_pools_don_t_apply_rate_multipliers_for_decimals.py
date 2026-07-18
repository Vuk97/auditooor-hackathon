"""
r76_stablecoin_rust/stable_swap_pools_don_t_apply_rate_multipliers_for_decimals.py

Rust sibling for Sol pattern: stable-swap-pools-don-t-apply-rate-multipliers-for-decimals
Bug class: stableswap-missing-rate-multipliers-decimal-normalization (applies_to: both)

This file re-exports from the existing r94_loop implementation.
"""
from __future__ import annotations

# Re-export from existing implementation
from r94_loop_stableswap_missing_rate_multipliers_decimal_normalization import run

__all__ = ["run"]
