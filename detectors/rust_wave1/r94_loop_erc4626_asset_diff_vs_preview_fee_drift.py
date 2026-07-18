"""
r94_loop_erc4626_asset_diff_vs_preview_fee_drift.py

Flags wrapper deposit fns that compute received assets as
`balance_after - balance_before` (post-fee) BUT issue shares using
`preview_deposit(amount_requested)` (pre-fee) — accounting drifts
by the underlying fee.

Source: Solodit #56950 (Burve).
Class: erc4626-asset-diff-vs-preview-fee-drift (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(deposit|_deposit|handle_deposit|forward_deposit)")
_BALANCE_DIFF_RE = re.compile(
    r"(balance_of|balance)\s*\([^;]{0,80}\)\s*-\s*(balance_before|prev_bal|before_bal|initial_bal)"
)
_PREVIEW_DEPOSIT_RE = re.compile(
    fr"preview_deposit\s*\(\s*{IDENT}amount\w*|previewDeposit\s*\(\s*{IDENT}amount\w*"
)
_SHARES_ARE_FROM_DIFF_RE = re.compile(
    r"shares\s*=\s*[^;]*(balance_of|balance)\s*\(\s*(self|address\(this\)|vault)|"
    r"previewDeposit\s*\(\s*(received|delta|diff|actual_received)"
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
        # we need BOTH: balance-diff calculation AND preview_deposit(amount-pre-fee)
        if not _BALANCE_DIFF_RE.search(body_nc):
            continue
        if not _PREVIEW_DEPOSIT_RE.search(body_nc):
            continue
        # exclude: shares are computed from the actual delta (no drift)
        if _SHARES_ARE_FROM_DIFF_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` measures received assets via "
                f"balance-diff (post-fee) but sizes shares with "
                f"preview_deposit(amount) (pre-fee) — mismatch drifts "
                f"wrapper accounting by the underlying fee "
                f"(erc4626-asset-diff-vs-preview-fee-drift). See "
                f"Solodit #56950 (Burve)."
            ),
        })
    return hits
