"""
r94_loop_erc4626_first_deposit_mint_vs_deposit_asymmetry.py

Flags ERC4626 vault source containing both deposit() and mint() whose
first-deposit branch (total_supply == 0) uses different conversion
logic (e.g. 1:1 in deposit, preview_mint + rounding in mint).

Source: Solodit #25797 (Astaria ERC4626-Cloned).
Class: erc4626-first-deposit-mint-vs-deposit-asymmetry (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of,
    is_pub, body_text_nocomment, source_nocomment,
)

_DEPOSIT_RE = re.compile(r"fn\s+deposit\s*\(")
_MINT_RE = re.compile(r"fn\s+mint\s*\(")
_FIRST_DEP_BRANCH_RE = re.compile(
    r"total_supply\s*\(\s*\)\s*==\s*0|totalSupply\s*\(\s*\)\s*==\s*0|"
    r"self\.total_supply\s*==\s*0|if\s+supply\s*==\s*0"
)
_ASYMMETRY_MARKERS_RE = re.compile(
    r"preview_mint|previewDeposit|round_up_div|ceil_div|\*\s*scale\s*/"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src_txt = source_nocomment(source)
    if not (_DEPOSIT_RE.search(src_txt) and _MINT_RE.search(src_txt)):
        return hits
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if name not in ("deposit", "mint"):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _FIRST_DEP_BRANCH_RE.search(body_nc):
            continue
        # Flag ONLY the mint() side (asymmetric-with-deposit branch)
        if name != "mint":
            continue
        # and ensure it uses ceil_div / preview-mint specific rounding
        if not _ASYMMETRY_MARKERS_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `mint` uses first-deposit branch with "
                f"rounding/preview logic while a sibling `deposit` "
                f"exists — first depositor gets different share count "
                f"by entry point (erc4626-first-deposit-mint-vs-deposit-"
                f"asymmetry). See Solodit #25797 (Astaria)."
            ),
        })
    return hits
