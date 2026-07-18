"""
r94_loop_deadline_block_timestamp_passthrough.py

Flags swap/router calls that pass `block_timestamp()` / `env.ledger.timestamp()`
/ `now` DIRECTLY as the deadline argument — the deadline check on the
sibling contract becomes a no-op.

Source: Solodit #18494 (Blueberry Update CurveSpell).
Class: deadline-block-timestamp-passthrough (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(swap|deposit|withdraw|stake|unstake|add_liquidity|remove_liquidity|borrow|repay)")
_SWAP_WITH_DEADLINE_RE = re.compile(
    r"\w+\s*\.\s*(swap|exact_input|exact_output|add_liquidity|remove_liquidity)\s*\([^;]*?(block_timestamp|env\.ledger\.timestamp|now\s*\(\s*\))",
    re.DOTALL,
)
_USES_CALLER_DEADLINE_RE = re.compile(
    r"deadline\s*:\s*(user_deadline|caller_deadline|params\.deadline|_deadline|deadline)\b"
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
        if not _SWAP_WITH_DEADLINE_RE.search(body_nc):
            continue
        if _USES_CALLER_DEADLINE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` passes block_timestamp / now directly "
                f"as the swap deadline — deadline check always passes, "
                f"stale pending txs execute (deadline-block-timestamp-"
                f"passthrough). See Solodit #18494 (Blueberry Update)."
            ),
        })
    return hits
