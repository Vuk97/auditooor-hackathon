"""
r94_loop_erc6909_partial_unwrap_fee_theft.py

Flags ERC-6909 wrapper unwrap fns whose "partial" variant (caller
passes a partial amount) transfers the WHOLE underlying NFT/token
without claiming accrued fees first — attacker partial-unwraps to
harvest fees, then re-wraps.

Source: Solodit #61328 (Cyfrin Vii UniswapV4Wrapper).
Class: erc6909-partial-unwrap-fee-theft (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(unwrap|unwrap_partial|partial_unwrap|redeem_partial)")
_PARTIAL_SIG_RE = re.compile(
    r"fn\s+\w+\s*\([^)]*\b(amount|share_amount|partial_amount|qty)\s*:"
)
_NFT_TRANSFER_RE = re.compile(
    fr"\.transfer_from\s*\(\s*\w+,\s*\w+,\s*{IDENT}token_id|"
    fr"transferFrom\s*\(\s*\w+,\s*\w+,\s*{IDENT}tokenId|"
    fr"underlying\s*\.\s*transfer_from|"
    fr"underlying\s*\.\s*safe_transfer_from"
)
_FEE_SETTLE_RE = re.compile(
    r"(collect_fees|claim_fees|settle_fees|harvest_fees|decrease_liquidity_and_collect|"
    r"burn_and_collect|take_fees)\s*\("
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        sig_text = snippet_of(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _PARTIAL_SIG_RE.search(sig_text):
            continue
        if not _NFT_TRANSFER_RE.search(body_nc):
            continue
        if _FEE_SETTLE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_text[:200],
            "message": (
                f"pub fn `{name}` is a partial-unwrap that transfers "
                f"the whole underlying NFT without settling accrued "
                f"fees first — attacker harvests fees via partial "
                f"unwrap (erc6909-partial-unwrap-fee-theft). See "
                f"Solodit #61328 (Vii)."
            ),
        })
    return hits
