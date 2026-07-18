"""
r94_loop_nested_erc4626_fee_not_accounted.py

Flags wrapper-vault fns that call `underlying.preview_deposit` /
`underlying.deposit` to size shares but don't subtract a deposit /
withdraw fee — user's minted share count overstates real value.

Source: Solodit #26369 (PoolTogether Vault).
Class: nested-erc4626-fee-not-accounted (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(deposit|withdraw|convert_to_shares|convert_to_assets|"
    r"preview_deposit|preview_withdraw|preview_mint)"
)
_USES_UNDERLYING_PREVIEW_RE = re.compile(
    r"(underlying|nested|inner_vault)\s*\.\s*(preview_deposit|preview_mint|preview_withdraw)\s*\("
)
_FEE_ACCOUNT_RE = re.compile(
    r"(deposit_fee|withdraw_fee|underlying_fee|entry_fee|exit_fee|fee_bps|"
    r"net_of_fee|after_fee_amount|amount_minus_fee)"
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
        if not _USES_UNDERLYING_PREVIEW_RE.search(body_nc):
            continue
        if _FEE_ACCOUNT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` sizes shares via underlying.preview_* "
                f"but never subtracts a deposit/withdraw fee — if the "
                f"underlying vault charges fees, wrapper issues "
                f"too many/few shares (nested-erc4626-fee-not-accounted). "
                f"See Solodit #26369 (PoolTogether)."
            ),
        })
    return hits
