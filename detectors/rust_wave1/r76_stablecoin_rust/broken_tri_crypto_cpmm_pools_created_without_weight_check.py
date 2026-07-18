"""
r76_stablecoin_rust/broken_tri_crypto_cpmm_pools_created_without_weight_check.py

Rust sibling for Sol pattern: broken-tri-crypto-cpmm-pools-created-without-weight-check
Bug class: cpmm-pool-creation-allows-n-gt-2-tokens-broken-math (applies_to: both)

This file re-exports from the existing r94_loop implementation.
"""
from __future__ import annotations

# Re-export from existing implementation
from r94_loop_cpmm_pool_creation_allows_n_gt_2_tokens_broken_math import run

__all__ = ["run"]
