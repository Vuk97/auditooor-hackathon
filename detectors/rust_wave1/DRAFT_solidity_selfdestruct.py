"""
DRAFT_solidity_selfdestruct.py

# DRAFT: auto-generated sibling for solidity-selfdestruct (source side: solidity).
# Review required before enabling. Do NOT add to test_detectors.sh yet.

BUG_CLASS: solidity-selfdestruct
description: EVM selfdestruct — Solidity-specific

Auto-translated from: reference/patterns.dsl/lido-deposit-blocked-by-attacker.yaml

This is a REVIEWER PROMPT — translation is best-effort from the Solidity
DSL regex/precondition shape into a tree-sitter-rust heuristic. Human must:
  1. Confirm the bug-class actually manifests on the Rust side (Soroban /
     Solana / Move / Sway / FunC / TON / CosmWasm). If not, delete this file
     and leave the class `solidity_only`.
  2. Replace the naive regex scan below with AST-level predicates matching
     the actual Rust shape of the bug (see e.g. delegatecall_to_user_address.py
     which ports EVM delegatecall → Soroban SEP-41 transfer-from spoof).
  3. Add fixtures: test_fixtures/DRAFT_solidity_selfdestruct_positive.rs
     and _negative.rs, then register in test_detectors.sh.
"""
from __future__ import annotations

import re

# TODO: import the specific _util helpers your AST predicate needs
from _util import line_col  # TODO  # noqa: F401


# Translated hint tokens from source-side regex (combine / refine as needed).
_HINT_RE = re.compile(r"lidoLocked|lidoBalance|lidoMirror|stETH\.balanceOf|IStETH\.balanceOf|_reconcile|updateMirror|syncBalance|_syncLidoBalance|snapshotBalance")  # TODO: replace with AST-shape predicate


def run(tree, source: bytes, filepath: str):
    """Best-effort text-regex port of the solidity-selfdestruct Solidity detector.

    TODO: upgrade from text-regex to tree-sitter-rust walk. This stub is
    intentionally over-eager to force the reviewer to think about
    positive/negative fixtures.
    """
    hits = []
    text = source.decode("utf-8", errors="replace")
    for m in _HINT_RE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        hits.append({
            "severity": "low",  # TODO: calibrate after fixtures
            "line": line,
            "col": 0,
            "snippet": m.group(0)[:160].replace("\n", " "),
            "message": (
                "DRAFT match for solidity-selfdestruct: "
                "EVM selfdestruct — Solidity-specific"
            ),
        })
    return hits


# --- Source-side excerpt (reference only) ------------------------------------
# # Auto-migrated by tools/dsl-migration-helper.py 2026-04-19 | pattern: lido-deposit-blocked-by-attacker | source: solodit-cluster-C0079 | severity: HIGH | confidence: LOW |  | # Contract-level: the target must keep a locally-mirrored copy of Lido's | # stETH / ETH state. The class covers stETH-shares vaults, Rock
