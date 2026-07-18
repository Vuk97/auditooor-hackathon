"""
r76_stablecoin_rust/rapid_borrow_repay_cycle_inflates_interest_rates.py

Rust sibling for Sol pattern: rapid-borrow-repay-cycle-inflates-interest-rates
Bug class: cdp-borrow-repay-cycle-rate-inflate-grief (applies_to: both)

This file re-exports from the existing r94_loop implementation.
"""
from __future__ import annotations

# Re-export from existing implementation
from r94_loop_cdp_borrow_repay_cycle_rate_inflate_grief import run

__all__ = ["run"]
