"""
r94_loop_erc4626_rounding_direction_mixed.py

Flags ERC4626 source where convertToShares and previewDeposit (or the
mirrored convertToAssets/previewWithdraw) use OPPOSITE rounding
directions (one floor/div, one ceil/mulDivUp) — arbitrage extracts
free shares or free assets.

Source: Solodit #25091 (Notional wfCashERC4626).
Class: erc4626-rounding-direction-mixed (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of,
    is_pub, body_text_nocomment,
)

_CONVERT_FN_RE = re.compile(r"(?i)^(convert_to_shares|convert_to_assets)$")
_PREVIEW_FN_RE = re.compile(r"(?i)^(preview_deposit|preview_mint|preview_withdraw|preview_redeem)$")

_CEIL_RE = re.compile(r"ceil_div|mul_div_up|round_up_div|\.ceil\s*\(|\+\s*1\s*\)\s*/")
_FLOOR_RE = re.compile(r"/\s*total_supply\s*\(\s*\)|/\s*total_assets\s*\(\s*\)|mul_div\s*\(")


def _has_ceil(text: str) -> bool:
    return bool(_CEIL_RE.search(text))


def _has_floor(text: str) -> bool:
    return bool(_FLOOR_RE.search(text))


def run(tree, source: bytes, filepath: str):
    hits = []
    convert_has_ceil = False
    convert_has_floor = False
    preview_has_ceil = False
    preview_has_floor = False
    first_offender = None
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        is_convert = bool(_CONVERT_FN_RE.search(name))
        is_preview = bool(_PREVIEW_FN_RE.search(name))
        if not (is_convert or is_preview):
            continue
        if _has_ceil(body_nc):
            if is_convert: convert_has_ceil = True
            if is_preview: preview_has_ceil = True
            first_offender = first_offender or (fn, name)
        if _has_floor(body_nc):
            if is_convert: convert_has_floor = True
            if is_preview: preview_has_floor = True
            first_offender = first_offender or (fn, name)
    # mixed direction = one side uses ceil, the other uses floor
    mixed = (convert_has_floor and preview_has_ceil) or (convert_has_ceil and preview_has_floor)
    if mixed and first_offender is not None:
        fn, name = first_offender
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"ERC4626 contract mixes rounding directions between "
                f"convert_to_* (floor) and preview_* (ceil) — arbitrage "
                f"extracts free shares/assets via the rounding gap "
                f"(erc4626-rounding-direction-mixed). See Solodit "
                f"#25091 (Notional)."
            ),
        })
    return hits
