"""
r94_loop_slippage_memory_var_not_propagated_unlimited.py

Flags swap wrapper fns that declare a local `slippage` / `min_out`
variable but never assign to it before passing it to the router —
effective slippage is 0, attacker sandwiches freely.

Source: Solodit #29680 (TrailOfBits Mass NestedDca).
Class: slippage-memory-var-not-propagated-unlimited (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(swap|nested_dca_swap|execute_swap|router_call|"
    r"exact_input|exact_output|swap_exact)"
)
# Declares slippage / min_out as a local but never assigns.
_DECLARE_NO_ASSIGN_RE = re.compile(
    fr"(?i)(let\s+{IDENT}slippage\w*\s*:\s*\w+\s*;|"
    fr"let\s+{IDENT}min_out\w*\s*:\s*\w+\s*;|"
    fr"uint256\s+{IDENT}slippage\w*\s*;|"
    fr"uint256\s+{IDENT}amountOutMin\w*\s*;)"
)
_ASSIGN_RE = re.compile(
    fr"(?i)({IDENT}slippage\w*\s*=\s*\w+|"
    fr"{IDENT}min_out\w*\s*=\s*\w+|"
    fr"{IDENT}amountOutMin\w*\s*=\s*\w+|"
    fr"{IDENT}amountOutMinimum\w*\s*=\s*\w+)"
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
        if not _DECLARE_NO_ASSIGN_RE.search(body_nc):
            continue
        if _ASSIGN_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` declares a local slippage / min_out "
                f"variable but never assigns a value before passing "
                f"it to the router — effective min-out is 0, "
                f"sandwich MEV extracts full value "
                f"(slippage-memory-var-not-propagated-unlimited). "
                f"See Solodit #29680 (TrailOfBits Mass NestedDca)."
            ),
        })
    return hits
