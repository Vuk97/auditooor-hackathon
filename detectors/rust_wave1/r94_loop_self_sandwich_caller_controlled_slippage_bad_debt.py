"""
r94_loop_self_sandwich_caller_controlled_slippage_bad_debt.py

Flags position open/close/reduce fns that forward a caller-controlled
`slippage` / `max_slippage_bps` argument DIRECTLY into the internal
swap — attacker sets slippage = u128::MAX, self-sandwiches, leaves
bad debt in vault.

Source: Solodit #20668 (Sherlock Unstoppable Vault).
Class: self-sandwich-caller-controlled-slippage-bad-debt (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(open_position|close_position|reduce_position|adjust_position|"
    r"leverage_position|flash_close)"
)
_CALLER_SLIPPAGE_ARG_RE = re.compile(
    r"fn\s+\w+\s*\([^)]*\b(slippage|max_slippage|slippage_bps|max_slippage_bps|max_impact_bps)\s*:"
)
_SWAP_FORWARDS_SLIPPAGE_RE = re.compile(
    fr"(\.swap|\.exact_input|\.exact_output|vault\.{IDENT}swap|pool\.{IDENT}swap|router\.{IDENT}swap)\s*\([^;]*(slippage|max_slippage|slippage_bps|max_slippage_bps|max_impact_bps)",
    re.DOTALL,
)
_CAPPED_SLIPPAGE_RE = re.compile(
    r"(slippage|max_slippage|slippage_bps|max_slippage_bps)\s*>\s*(MAX_SLIPPAGE|max_allowed|protocol_max|500|1000)|"
    r"assert[!_]?\s*\(\s*(slippage|max_slippage)\s*<=\s*(MAX_SLIPPAGE|max_allowed|protocol_max)|"
    r"require\s*\(\s*(slippage|max_slippage)\s*<=\s*(MAX_SLIPPAGE|max_allowed|protocol_max)"
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
        sig_text = snippet_of(fn, source)
        if not _CALLER_SLIPPAGE_ARG_RE.search(sig_text):
            continue
        if not _SWAP_FORWARDS_SLIPPAGE_RE.search(body_nc):
            continue
        if _CAPPED_SLIPPAGE_RE.search(body_nc + sig_text):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_text[:200],
            "message": (
                f"pub fn `{name}` forwards caller-controlled slippage "
                f"to the internal swap with no upper cap — attacker "
                f"self-sandwiches at max slippage, leaves bad debt "
                f"(self-sandwich-caller-controlled-slippage-bad-debt). "
                f"See Solodit #20668 (Unstoppable)."
            ),
        })
    return hits
