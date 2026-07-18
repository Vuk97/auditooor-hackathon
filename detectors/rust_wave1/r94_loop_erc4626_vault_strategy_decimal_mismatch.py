"""
r94_loop_erc4626_vault_strategy_decimal_mismatch.py

Flags vault fns that call a strategy with an asset amount but neither
scale up/down to the strategy's decimals — a 10^N mismatch inflates
or deflates share price.

Source: Solodit #49643 (BakerFi StrategyLeverage).
Class: erc4626-vault-strategy-decimal-mismatch (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(deposit|withdraw|redeem|convert_to_shares|convert_to_assets|"
    r"total_assets|preview_deposit|preview_withdraw)"
)
_STRATEGY_CALL_RE = re.compile(
    r"(strategy|underlying|lending_pool|lender|adapter)\s*\.\s*(deposit|withdraw|redeem|supply|borrow)\s*\("
)
_SCALE_RE = re.compile(
    r"(scale|10u?(\d+)\*\*|10\.pow\s*\(|decimals_diff|vault_decimals|strategy_decimals|\*\s*10u\d+\.pow|\s*<<\s*\d+)"
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
        if not _STRATEGY_CALL_RE.search(body_nc):
            continue
        if _SCALE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` forwards assets to the strategy "
                f"without a 10^N scale factor — vault/strategy decimal "
                f"mismatch inflates share price (erc4626-vault-"
                f"strategy-decimal-mismatch). See Solodit #49643 "
                f"(BakerFi)."
            ),
        })
    return hits
