"""
r94_loop_fee_config_intermediate_overflow_vault_drain.py

Flags PnL / fee math that computes `position * price * fee_bps`
(three-way multiplication) in a single expression with large
denominators — intermediate overflow wraps u256, attacker drains
vault.

Source: Solodit #6322 (Tigris Trade).
Class: fee-config-intermediate-overflow-vault-drain (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(pnl|fee|compute_fee|calc_fee|realize_pnl)")
_TRIPLE_MUL_RE = re.compile(
    r"\w+\s*\*\s*\w+\s*\*\s*\w+\s*/\s*\w*1[eE_]?[0-9_]*|"
    r"position\w*\s*\.\s*checked_mul\s*\(\s*price\w*\s*\)\s*\.\s*unwrap\s*\(\s*\)\s*\.\s*checked_mul\s*\(\s*fee\w*|"
    r"position\w*\s*\*\s*price\w*\s*\*\s*(fee|bps)"
)
_MULDIV_SAFE_RE = re.compile(
    r"mul_div|full_math|FullMath\.mulDiv|math::mul_div|safe_mul_div|mulDiv\s*\("
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _TRIPLE_MUL_RE.search(body_nc):
            continue
        if _MULDIV_SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` performs `a * b * c / 1e_N` 3-way "
                f"multiplication without mulDiv / FullMath — "
                f"intermediate overflows u256 for certain fee "
                f"configs, wraps to tiny value (fee-config-"
                f"intermediate-overflow-vault-drain). See Solodit "
                f"#6322 (Tigris Trade)."
            ),
        })
    return hits
