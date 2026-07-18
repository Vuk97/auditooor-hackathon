"""
r94_loop_safe_fallback_handler_setter_missing_address_guard.py

Flags Gnosis-Safe Guard / module fns that permit a caller to
invoke `setFallbackHandler(newHandler)` without whitelisting the
handler address. Attacker-borrower sets fallback to their own
contract and hijacks ERC721 / ERC1155 callbacks (onReceive,
operator approvals) routed through the Safe.

Source: Solodit #30522 (Code4rena reNFT Guard).
Class: safe-fallback-handler-setter-missing-address-guard (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(check_transaction|check_safe_call|"
    r"pre_exec|preExec|pre_execution|"
    r"validate_safe_tx|validateSafeTx|"
    r"check_after_execution|checkAfterExecution)"
)
_FALLBACK_SIG_RE = re.compile(
    r"(?i)(setFallbackHandler|set_fallback_handler|"
    r"0xf08a0323|fallbackHandler\s*=)"
)
# Safe: validates handler address against a whitelist / reverts / require.
_GUARD_RE = re.compile(
    r"(?i)(require\s*\(\s*\w*(handler|newHandler)\s*==\s*|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}handler\s*==\s*|"
    fr"whitelist\s*\[\s*{IDENT}handler|"
    r"allowed_fallback_handlers|"
    r"is_allowed_fallback\s*\(|"
    r"revert\s*\(|panic!\s*\(|"
    r"selector\s*==\s*SETFALLBACK_SELECTOR\s*\)\s*\{\s*[\s\S]*?revert)"
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
        if not _FALLBACK_SIG_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` (Safe Guard) observes a "
                f"`setFallbackHandler` call but does not whitelist / "
                f"revert on arbitrary handler addresses — attacker-"
                f"borrower points fallback at their own contract and "
                f"hijacks NFT / 1155 callbacks "
                f"(safe-fallback-handler-setter-missing-address-guard). "
                f"See Solodit #30522 (Code4rena reNFT Guard)."
            ),
        })
    return hits
