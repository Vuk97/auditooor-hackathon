"""
r94_loop_erc20_no_revert_on_failure_return_value_ignored_shares_mint.py

Flags deposit / join / stake fns that call `token.transferFrom`
without checking the returned bool or using SafeERC20, and then
mint / record shares for the caller. Some ERC20s (BNB, ZRX,
EURS) return false on failure instead of reverting — attacker
deposits nothing but still receives shares.

Source: Solodit #32370 (Sherlock Teller Finance LenderGroup).
Class: erc20-no-revert-on-failure-return-value-ignored-shares-mint (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(deposit|join_pool|add_to_group|add_liquidity|"
    r"stake|mint_shares|supply|contribute|buy_shares)"
)
# transferFrom called without `require(...)` and followed by share mint / record.
_UNCHECKED_AND_MINT_RE = re.compile(
    r"(?i)(token\.\s*transfer_from\s*\([\s\S]{0,120}?\)\s*;[\s\S]{0,200}?(_mint|mint_shares|shares\s*\+=|balances\s*\[\s*\w+\s*\]\s*\+=)|"
    r"ierc20\s*\.\s*transfer_from\s*\([\s\S]{0,120}?\)\s*;[\s\S]{0,200}?_mint|"
    r"IERC20\s*\(\s*\w+\s*\)\s*\.\s*transferFrom\s*\([\s\S]{0,120}?\)\s*;[\s\S]{0,200}?_mint)"
)
# Safe: return value checked or SafeERC20 used.
_CHECKED_RE = re.compile(
    fr"(?i)(require\s*\(\s*{IDENT}token\s*\.\s*transfer_?from|"
    fr"require\s*\(\s*IERC20\s*\(\s*\w+\s*\)\s*\.\s*transferFrom|"
    fr"SafeERC20|safeTransferFrom|"
    fr"bool\s+success\s*=\s*{IDENT}token\.transfer_from|"
    fr"bool\s+ok\s*=|assert\s*\(\s*token\.transfer_from|"
    fr"let\s+\w+\s*=\s*token\s*\.\s*transfer_from[\s\S]{{0,60}}assert)"
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
        if not _UNCHECKED_AND_MINT_RE.search(body_nc):
            continue
        if _CHECKED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls `token.transferFrom` without "
                f"checking the returned bool / using SafeERC20, and "
                f"then mints shares — non-reverting tokens (BNB, ZRX, "
                f"EURS) return false on failure so attacker deposits "
                f"nothing and still receives shares "
                f"(erc20-no-revert-on-failure-return-value-ignored-shares-mint). "
                f"See Solodit #32370 (Sherlock Teller Finance)."
            ),
        })
    return hits
