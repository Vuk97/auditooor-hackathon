"""
r94_loop_oracle_readonly_reentrancy.py

Flags oracle reads against Balancer/Curve pool views without a
readonly-reentrancy guard (checkNotInVaultContext / _nonReentrant).

Source: Solodit #18493 (Sherlock Blueberry Balancer).
Class: oracle-readonly-reentrancy (rust side closer).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(get_price|price_of|peek|spot_price)")
_POOL_READ_RE = re.compile(
    r"BalancerVault\.getPoolTokens|balancer_vault\.get_pool_tokens|"
    r"CurvePool\.price_oracle|curve_pool\.get_virtual_price|"
    r"pool\.get_pool_tokens\(|pool\.virtual_price\("
)
_GUARD_RE = re.compile(
    r"check_?not_?in_?vault_?context|_nonReentrant|readonly_reentrancy_check|"
    r"ensure_?not_?in_?vault_?context|vault\.ensureNotInVault",
    re.IGNORECASE,
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
        if not _POOL_READ_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads Balancer/Curve pool state "
                f"without readonly-reentrancy guard. Attacker reentrantly "
                f"manipulates pool mid-oracle-read. See Solodit #18493 "
                f"(Blueberry)."
            ),
        })
    return hits
