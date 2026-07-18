"""
r94_loop_vault_donation_locks_ratio_permanent.py

Flags deposit fns that compute shares as `total_supply * amount /
total_assets` without a virtual-share / min-supply guard — first
depositor / donator can lock ratio at 1 by donating pre-deposit.

Source: Solodit #51635 (Halborn Tagus Labs V2).
Class: vault-donation-locks-ratio-permanent (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(deposit|mint|wrap|pocket_deposit)")
_RATIO_CALC_RE = re.compile(
    fr"(total_supply|totalSupply)\s*\(\s*\)\s*\*\s*{IDENT}amount[\s\S]{{0,80}}?/\s*(total_assets|totalAssets)\s*\(\s*\)|"
    fr"{IDENT}amount\s*\*\s*(total_supply|totalSupply)\s*\(\s*\)\s*/\s*(total_assets|totalAssets)\s*\(\s*\)|"
    fr"{IDENT}amount\s*\*\s*{IDENT}shares\s*/\s*{IDENT}assets"
)
_VIRTUAL_SHARE_RE = re.compile(
    fr"DECIMAL_OFFSET|VIRTUAL_SHARES|virtual_shares|virtual_assets|"
    fr"\+\s*10\s*\*\*\s*\d+|\+\s*1\s*(?:,|\))|"
    fr"total_supply\s*\(\s*\)\s*==\s*0\s*\?\s*{IDENT}amount"
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
        if not _RATIO_CALC_RE.search(body_nc):
            continue
        if _VIRTUAL_SHARE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` mints shares as "
                f"total_supply * amount / total_assets with no "
                f"virtual-share or first-deposit guard — donator "
                f"locks ratio at 1 permanently (vault-donation-"
                f"locks-ratio-permanent). See Solodit #51635 "
                f"(Tagus Labs)."
            ),
        })
    return hits
