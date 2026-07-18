"""
r76_stablecoin_rust/liquidation_leaves_zombie_debt_on_borrower.py

Rust sibling for Sol pattern: liquidation-leaves-zombie-debt-on-borrower
Bug class: liquidation-partial-settlement-leaves-zombie-debt (applies_to: both)

This file re-exports from the existing r94_loop implementation.
"""
from __future__ import annotations

# Re-export from existing implementation
from r94_loop_liquidation_partial_settlement_leaves_zombie_debt import run

__all__ = ["run"]
