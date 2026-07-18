"""
r76_stablecoin_rust/stableswap_disjoint_swaps_break_invariant.py

Rust sibling for Sol pattern: stableswap-disjoint-swaps-break-invariant
Bug class: stableswap-disjoint-multihop-breaks-invariant (applies_to: both)

This file re-exports from the existing r94_loop implementation.
"""
from __future__ import annotations

# Re-export from existing implementation
from r94_loop_stableswap_disjoint_multihop_breaks_invariant import run

__all__ = ["run"]
