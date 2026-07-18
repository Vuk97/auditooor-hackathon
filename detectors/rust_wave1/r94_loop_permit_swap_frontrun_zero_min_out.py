"""
r94_loop_permit_swap_frontrun_zero_min_out.py

Flags swap fns that accept BOTH a user-permit signature and a
caller-controlled amount_out_min (or min_out/deadline pair) — a
searcher steals the permit, calls the swap with amount_out_min=0,
and sandwiches the victim's original tx.

Source: Solodit #53124 (Cork FlashSwapRouter permit MEV).
Class: permit-swap-frontrun-zero-min-out (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(swap_ra_for_ds|swap_ds_for_ra|swap_with_permit|permit_and_swap|"
    r"swap_exact_in_permit|swap_exact_out_permit|swap_and_deposit_permit)"
)
_PERMIT_PARAM_RE = re.compile(
    r"(permit_sig|permit_signature|rawRaPermitSig|permit_v|raw_permit|"
    r"permit_data|permit2_sig|witness)"
)
_MIN_OUT_USED_RE = re.compile(
    r"(amount_out_min|amountOutMin|min_out|minAmountOut|min_output|output_min)\b"
)
_SIG_TO_OUT_BINDING_RE = re.compile(
    r"(hash_with_min_out|digest_bound_min|permit_bound_amt|permit_struct\s*\.\s*min|"
    r"amount_out_min\s*==\s*permit\.min|witness\s*\.\s*min)"
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
        # also scan the params header
        sig_text = snippet_of(fn, source)
        if not _PERMIT_PARAM_RE.search(sig_text + body_nc):
            continue
        if not _MIN_OUT_USED_RE.search(sig_text + body_nc):
            continue
        if _SIG_TO_OUT_BINDING_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_text[:200],
            "message": (
                f"pub fn `{name}` bundles a user permit sig with a "
                f"caller-controlled amount_out_min — searcher extracts "
                f"permit and submits at amount_out_min=0, sandwiching "
                f"the victim (permit-swap-frontrun-zero-min-out). "
                f"See Solodit #53124 (Cork FlashSwapRouter)."
            ),
        })
    return hits
