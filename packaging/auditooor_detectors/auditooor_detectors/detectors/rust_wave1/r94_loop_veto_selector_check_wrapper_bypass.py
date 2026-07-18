"""
r94_loop_veto_selector_check_wrapper_bypass.py

Flags veto/guardian fns that inspect a proposal's calldata selector
(first 4 bytes / first u32) against a blacklist without recursing into
wrapper calls (e.g. multicall / Proxy.upgradeTo / delegatecall
wrappers).

Source: Solodit #1246 (Vader Council veto bypass).
Class: veto-selector-check-wrapper-bypass (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(veto|can_veto|validate_veto|guardian_veto|block_proposal)")
_SELECTOR_CHECK_RE = re.compile(
    r"selector|first_4_bytes|bytes4\s*\(|first\s*\(\s*4\s*\)|"
    r"calldata\[0\s*\.\.\s*4\s*\]|selector\s*==\s*|selector\s*!=\s*|"
    r"(tx\.selector|action\.selector|cd\.selector)"
)
_RECURSIVE_DECODE_RE = re.compile(
    r"(decode_inner|extract_inner_call|is_multicall|is_wrapped_call|"
    r"recurse_selector|unwrap_multicall|decode_multicall|foreach_inner_call)"
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
        if not _SELECTOR_CHECK_RE.search(body_nc):
            continue
        if _RECURSIVE_DECODE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` veto/guardian checks the outer "
                f"selector but never recurses into multicall/wrapper "
                f"calls — forbidden action can be nested inside a "
                f"wrapper and bypass the check (veto-selector-check-"
                f"wrapper-bypass). See Solodit #1246 (Vader)."
            ),
        })
    return hits
