"""
r94_loop_usdt_non_standard_return_missing_safetransfer.py

Flags fns that call `IERC20(token).transferFrom(...)` / `transfer(...)`
where the expected return is a `bool` but use a raw IERC20
interface — USDT (and similar) return `void`, so Solidity's ABI
decoder reverts on the empty return data. Contracts that handle
arbitrary ERC20 tokens must use `SafeERC20.safeTransferFrom` /
`safeTransfer`.

Source: Solodit #18109 (TrailOfBits Meson Protocol).
Class: usdt-non-standard-return-missing-safetransfer (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(deposit|withdraw|swap|release|fund|transfer_asset|"
    r"pay_out|execute_transfer|pull_token|push_token)"
)
# Calls IERC20.transfer / transferFrom directly with return-value decode.
_RAW_IERC20_RE = re.compile(
    r"(?i)(IERC20\s*\(\s*\w+\s*\)\s*\.\s*transfer(From)?\s*\(|"
    r"ierc20\s*::\s*transfer(_from)?\s*\(|"
    fr"{IDENT}token\w*\s*\.\s*transfer(_from)?\s*\([\s\S]{{0,80}}?\)\s*;|"
    fr"{IDENT}handle\w*\s*\.\s*transfer(_from)?\s*\([\s\S]{{0,80}}?\)\s*;|"
    r"require\s*\(\s*IERC20\s*\(\s*\w+\s*\)\s*\.\s*transfer(From)?\s*\()"
)
# Safe: SafeERC20 / safeTransfer / forceApprove.
_SAFE_WRAPPER_RE = re.compile(
    r"(?i)(SafeERC20|safeTransfer(From)?\s*\(|"
    r"safeIncreaseAllowance|forceApprove|"
    r"safe_transfer(_from)?\s*\(|"
    r"using\s+SafeERC20|"
    r"IERC20Metadata\s*\(\s*\w+\s*\)\s*\.\s*safeTransfer)"
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
        if not _RAW_IERC20_RE.search(body_nc):
            continue
        if _SAFE_WRAPPER_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls IERC20.transfer(From) directly "
                f"without SafeERC20 — tokens like USDT that return "
                f"`void` cause Solidity to revert on empty return "
                f"data, breaking transfers with real-world tokens "
                f"(usdt-non-standard-return-missing-safetransfer). "
                f"See Solodit #18109 (TrailOfBits Meson Protocol)."
            ),
        })
    return hits
