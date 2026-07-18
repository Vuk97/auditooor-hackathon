"""
r94_loop_pause_state_not_propagated_to_sibling_contracts.py

Flags pub fns on a sibling contract (Adapter / Helper / CTF / NegRisk /
Operator / Collateral / Clearing / Hook) that perform token motion
(redeem / split / merge / convert / mint / burn / transfer) without
consulting the companion exchange / hub's pause flag and without any
local pause guard. Cross-contract pause-state desync — emergency pause
on the hub is bypassable via the sibling.

Source: Cantina #182 / Polymarket SKILL_ISSUE #217.
Class: pause-state-not-propagated-to-sibling-contracts (both).
Heuristic; LOW confidence.
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(redeem_positions|redeemPositions|"
    r"split_position|splitPosition|"
    r"merge_positions|mergePositions|"
    r"convert_positions|convertPositions|"
    r"redeem|unwrap|mint|burn|settle|execute)"
)
_TOKEN_MOTION_RE = re.compile(
    r"(?i)(transfer\s*\(|safe_transfer\s*\(|safeTransfer\s*\(|"
    r"transfer_from\s*\(|transferFrom\s*\(|"
    r"\.mint\s*\(|\.burn\s*\(|deposit\s*\(|withdraw\s*\()"
)
_PAUSE_CHECK_RE = re.compile(
    r"(?i)(is_paused|isPaused|\.paused\s*\(\s*\)|"
    r"require\s*\(\s*!\s*paused|when_not_paused|whenNotPaused|"
    r"_check_pause|only_when_active|exchange\.paused|"
    r"assert\w*\s*\(\s*!\s*\w*paused|exchange_paused)"
)
_SIBLING_HINT_RE = re.compile(
    r"(?i)(adapter|collateral|hook|helper|sibling|ctf|"
    r"neg_?risk|operator|clearing)"
)


def run(tree, source: bytes, filepath: str):
    src_text = source.decode("utf-8", errors="ignore")
    # Sibling-shape gate at file/contract level (regex on full source text).
    if not _SIBLING_HINT_RE.search(src_text):
        return []
    # Skip files that ARE Pausable themselves.
    if re.search(r"(?i)(Pausable|when_not_paused|whenNotPaused)", src_text):
        return []
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
        if not _TOKEN_MOTION_RE.search(body_nc):
            continue
        if _PAUSE_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} on sibling contract performs token motion "
                f"without consulting hub/exchange pause state and without a "
                f"local pause guard — cross-contract pause-state desync "
                f"(pause-state-not-propagated-to-sibling-contracts). "
                f"Polymarket Cantina #182."
            ),
        })
    return hits
