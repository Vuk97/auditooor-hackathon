"""
r94_loop_per_user_baseline_not_initialized.py

Flags deposit-style fns that persist a new per-user position struct
without initializing its `amount_claimed` / `checkpoint` / `baseline`
field to the current global accumulator value.

Source: Solodit #6533 (Alchemix Fair Funding).
Class: per-user-baseline-not-initialized (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(deposit|create_position|open_stake|stake|mint_shares)")
_GLOBAL_ACC_RE = re.compile(
    r"amount_claimable_per_share|reward_per_token_stored|accumulator|"
    r"global_index|total_index"
)
_POSITION_WRITE_RE = re.compile(
    r"positions?\s*\[[^\]]+\]\s*=\s*\w+\s*\{|"
    r"Position\s*\{[^}]*amount\b|"
    r"new_position\s*=\s*Position|"
    r"positions?\.insert\s*\(|positions?\[\s*\w+\s*\]\s*="
)
_BASELINE_INIT_RE = re.compile(
    fr"amount_claimed\s*:\s*({IDENT}amount_claimable_per_share|accumulator|global_index)|"
    fr"checkpoint\s*:\s*{IDENT}global|baseline\s*:\s*{IDENT}accumulator|"
    r"position\.amount_claimed\s*=\s*amount_claimable_per_share"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        # Check sig AND body for global accumulator (may appear only as param)
        fn_text = text_of(fn, source)
        if not _GLOBAL_ACC_RE.search(fn_text):
            continue
        if not _POSITION_WRITE_RE.search(body_nc):
            continue
        if _BASELINE_INIT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` creates a new user position with a "
                f"global accumulator in scope but does not initialize "
                f"the user's per-baseline (amount_claimed/checkpoint/"
                f"baseline) to that accumulator. Yield misallocation. "
                f"See Solodit #6533 (Fair Funding Alchemix)."
            ),
        })
    return hits
