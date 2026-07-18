"""Canonical dollar-impact derivation labels - SINGLE SOURCE OF TRUTH.

Shared by two consumers that MUST agree, so they cannot silently drift apart:

  - tools/absolute-usd-derivation-check.py  (pre-submit Check #148 gate): the four
    required derivation parts a HIGH+ fund-loss finding on a floor-declaring program
    must carry (asset-identity / unit->USD / market-size / absolute-$ vs floor).
  - tools/dispatch-agent-with-prebriefing.py (Drive-and-Verify Paste-Ready Mandate):
    the four mandatory ABSOLUTE $-IMPACT PROOF lines a filing lane is told to complete
    BEFORE calling a draft paste-ready.

The brief INSTRUCTS an agent what to write; the gate CHECKS what was written. If the
two hard-code their own label strings they drift (the brief says "Backing artifact"
while the gate scores "absolute-vs-floor", etc.). Binding both to this one tuple - and
asserting equality in a test - makes drift a test failure, not a silent hole.

DOLLAR_IMPACT_DERIVATION_LABELS is ordered (a)->(d) to line up 1:1 with
DERIVATION_PART_KEYS (the gate's derivation_parts dict keys).
"""
from __future__ import annotations

from typing import Tuple

# Ordered (a)-(d). These exact strings appear verbatim in BOTH the gate's
# required-derivation labels and the brief's mandate proof-line prefixes.
DOLLAR_IMPACT_DERIVATION_LABELS: Tuple[str, ...] = (
    "Asset identity",
    "Unit->USD",
    "Market-size scenario",
    "Absolute $ vs floor",
)

# The gate's derivation_parts dict keys, aligned 1:1 (same order) with the labels above.
DERIVATION_PART_KEYS: Tuple[str, ...] = (
    "asset_identity",
    "unit_to_usd",
    "market_size",
    "absolute_vs_floor",
)
