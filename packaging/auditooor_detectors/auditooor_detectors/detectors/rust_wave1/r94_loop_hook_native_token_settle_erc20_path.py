"""
r94_loop_hook_native_token_settle_erc20_path.py

Flags Uniswap-V4 style hook settle / take / sync fns that call
an IERC20 transfer / transferFrom helper without branching on
`currency.is_address_zero()` / `is_native()` first — native-token
(ETH) pool operations revert or strand funds because the hook
path never dispatches to `msg.value` / `poolManager.settle{value:}`.

Source: Solodit #49299 (OpenZeppelin Uniswap Hooks Library M1).
Class: hook-native-token-settle-erc20-path (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(settle|take|sync|pay_pool_manager|"
    r"before_swap|after_swap|before_modify_liquidity|after_modify_liquidity|"
    r"credit_currency|debit_currency)"
)
# Must call an ERC20 path.
_ERC20_PATH_RE = re.compile(
    fr"(?i)(\bsafe_transfer\s*\(|safeTransfer\s*\(|"
    fr"\bsafe_transfer_from\s*\(|safeTransferFrom\s*\(|"
    fr"\bIERC20\s*\(|ERC20Interface|"
    fr"\btransfer_from\s*\(\s*{IDENT}currency|"
    fr"\btoken\s*\.\s*transfer_from\s*\()"
)
# Safe: native branch check.
_NATIVE_BRANCH_RE = re.compile(
    r"(?i)(currency\.is_address_zero|currency\.isAddressZero|"
    r"is_native\s*\(|isNative\s*\(|"
    r"currency\s*==\s*CurrencyLibrary::NATIVE|"
    r"address\s*\(\s*currency\s*\)\s*==\s*address\s*\(\s*0|"
    r"currency\.to_id\s*\(\s*\)\s*==\s*0|"
    r"msg\.value|self\.env\(\)\.ledger\(\)\.value)"
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
        if not _ERC20_PATH_RE.search(body_nc):
            continue
        if _NATIVE_BRANCH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls an ERC20 transfer/transferFrom "
                f"path without first branching on `currency.is_native()` "
                f"/ `isAddressZero()` — ETH-based V4 pools revert or "
                f"strand funds because the native settle path is never "
                f"dispatched "
                f"(hook-native-token-settle-erc20-path). "
                f"See Solodit #49299 (OpenZeppelin Uniswap Hooks M1)."
            ),
        })
    return hits
