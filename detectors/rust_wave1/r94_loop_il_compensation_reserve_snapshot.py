"""
r94_loop_il_compensation_reserve_snapshot.py

Flags burn / withdraw / redeem fns that compute impermanent-loss
compensation from CURRENT reserves without a delay/TWAP.

Source: Solodit #1239 (Vader Protocol).
Class: il-compensation-reserve-snapshot (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(burn|withdraw|redeem|exit_position|unwind)")
_IL_RE = re.compile(r"impermanent_loss|il_compensation|il_protect|compensate_il|protocol_reserves")
_SAFE_RE = re.compile(r"twap|vault_oracle|snapshot_block|delay_window|rolling_average")


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
        if not _IL_RE.search(body_nc):
            continue
        if _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes impermanent-loss compensation "
                f"from current reserves (no TWAP / delay). Flash-skewed "
                f"reserves inflate the IL claim. See Solodit #1239 "
                f"(Vader Protocol)."
            ),
        })
    return hits
