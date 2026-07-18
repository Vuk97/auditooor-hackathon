"""
r94_loop_lsd_stake_internal_deposit_no_slippage.py

Flags stake/unstake/rebalance fns that internally call an LSD/LST
adapter (rETH/stETH/cbETH/frxETH) `deposit`/`stake` without passing
a min-received / min-out value — stakers are sandwichable.

Source: Solodit #19923 (Asymmetry SafEth).
Class: lsd-stake-internal-deposit-no-slippage (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(stake|unstake|rebalance|rebalance_to_weight|mint_saf|redeem_saf)")
_LST_CALL_RE = re.compile(
    r"(reth|steth|cbeth|frxeth|sfrxeth|saf_eth|wsteth|lst|lsd)\s*\.\s*(deposit|stake|mint|submit)\s*\("
)
_MIN_OUT_ARG_RE = re.compile(
    r"(min_received|min_out|min_amount_out|amount_out_min(imum)?)\s*[:=,]"
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
        if not _LST_CALL_RE.search(body_nc):
            continue
        if _MIN_OUT_ARG_RE.search(body_nc + "\n" + sig_text):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` internally deposits into an LST/"
                f"LSD adapter without a min-received / min-out check "
                f"— stakers are sandwichable (lsd-stake-internal-"
                f"deposit-no-slippage). See Solodit #19923 (Asymmetry)."
            ),
        })
    return hits
