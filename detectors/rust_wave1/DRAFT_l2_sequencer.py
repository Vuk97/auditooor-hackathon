"""
DRAFT_l2_sequencer.py

# DRAFT: auto-generated sibling for l2-sequencer (source side: solidity).
# Review required before enabling. Do NOT add to test_detectors.sh yet.

BUG_CLASS: l2-sequencer
description: L2 sequencer uptime oracle — EVM-L2 specific

Auto-translated from: reference/patterns.dsl/r74-oracle-no-l2-sequencer-grace-window.yaml

This is a REVIEWER PROMPT — translation is best-effort from the Solidity
DSL regex/precondition shape into a tree-sitter-rust heuristic. Human must:
  1. Confirm the bug-class actually manifests on the Rust side (Soroban /
     Solana / Move / Sway / FunC / TON / CosmWasm). If not, delete this file
     and leave the class `solidity_only`.
  2. Replace the naive regex scan below with AST-level predicates matching
     the actual Rust shape of the bug (see e.g. delegatecall_to_user_address.py
     which ports EVM delegatecall → Soroban SEP-41 transfer-from spoof).
  3. Add fixtures: test_fixtures/DRAFT_l2_sequencer_positive.rs
     and _negative.rs, then register in test_detectors.sh.
"""
from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    functions_in_contractimpl,
    is_pub,
    line_col,
    snippet_of,
)


_FN_NAME_RE = re.compile(r"(?i)(get_price|fetch_price|quote_price|read_price|latest_price)")
_PRICE_READ_RE = re.compile(
    r"(?i)(latest_round_data\s*\(|latestRoundData\s*\(|getAnswer\s*\(|getPrice\s*\()"
)
_SEQUENCER_RE = re.compile(r"(?i)(sequencer|uptime_feed|sequencer_uptime|l2_uptime)")
_GRACE_RE = re.compile(
    r"(?i)(GRACE_PERIOD|gracePeriod|grace_period|started_at|startedAt|"
    r"time_since_up|sequencerUpAtLeast|env\.ledger\(\)\.timestamp\(\)\s*-\s*"
    r"[\w\.]*started_at|block\.timestamp\s*-\s*[\w\.]*startedAt)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _PRICE_READ_RE.search(body_nc):
            continue
        if _SEQUENCER_RE.search(body_nc) and _GRACE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "low",  # TODO: calibrate after fixtures
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source),
            "message": (
                f"pub fn `{name}` reads an oracle price but shows no L2 "
                "sequencer uptime/grace-window guard. When a sequencer comes "
                "back up, stale oracle values can be consumed immediately."
            ),
        })
    return hits


# --- Source-side excerpt (reference only) ------------------------------------
# # Auto-migrated by tools/dsl-migration-helper.py 2026-04-19 | pattern: r74-oracle-no-l2-sequencer-grace-window | source: r74b-cross-firm-cs+oz | severity: MEDIUM | confidence: LOW | tier: D |  | # R74-B cross-firm promotion (oracle-cascade, 4/4 firms). | # Source stubs merged: | #   - cs/oracle-manipulation-on-l2.yam
