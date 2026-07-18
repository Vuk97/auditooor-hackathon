"""
r76_stablecoin_rust/liquidation_dosed_by_collateral_reserve_illiquidity.py

Rust sibling for Sol pattern: liquidation-dosed-by-collateral-reserve-illiquidity
Bug class: liquidation-atoken-burn-reserve-illiquidity-dos (applies_to: both)

This file re-exports from the existing r94_loop implementation.
"""
from __future__ import annotations

# Re-export from existing implementation
from r94_loop_liquidation_atoken_burn_reserve_illiquidity_dos import run

__all__ = ["run"]
