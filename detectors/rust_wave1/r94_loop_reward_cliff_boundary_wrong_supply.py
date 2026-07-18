"""
r94_loop_reward_cliff_boundary_wrong_supply.py

Flags reward-mint fns that compute cliff-index from post-mint supply
instead of pre-mint supply (CVX/AURA-style cliff boundary bug).

Source: Solodit #24319 (Aura Finance / Convex cliff-boundary miscalc).
Class: reward-cliff-boundary-wrong-supply (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(mint|reward|earn|claim|distribute)")
_CLIFF_RE = re.compile(r"cliff|reduction|totalCliffs|total_cliffs")
_POST_MINT_RE = re.compile(
    r"(total_supply|totalSupply)\s*\(\s*\)\s*\+\s*(amount|_amount|mint_amount)|"
    r"\.mint\s*\([^)]*\)[\s;]*(let|cliff\s*=)|"
    r"(cliff|reduction)\s*=\s*(total_supply|totalSupply)\s*\(\s*\)\s*/"
)
_SAFE_RE = re.compile(r"pre_mint_supply|supplyBeforeMint|cached_supply|snapshotSupply")


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
        if not _CLIFF_RE.search(body_nc):
            continue
        if not _POST_MINT_RE.search(body_nc):
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
                f"pub fn `{name}` computes cliff/reduction index from "
                f"post-mint total_supply — at cliff boundary the reward "
                f"amount is mis-calculated (reward-cliff-boundary-wrong-supply). "
                f"See Solodit #24319 (Aura/Convex)."
            ),
        })
    return hits
