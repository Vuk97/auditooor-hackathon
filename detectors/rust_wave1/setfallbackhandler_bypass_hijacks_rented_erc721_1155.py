"""
setfallbackhandler_bypass_hijacks_rented_erc721_1155

Auto-generated sibling for Solodit #30522 calibration.
Pattern class: setfallbackhandler-bypass-hijacks-rented-erc721-1155
Platform: solana
Source: phase7_rust_fixture_setfallbackhandler_bypass_hijacks_rented_erc721_1155.json

This detector remains intentionally narrow and unpromoted. It only flags
public fallback-handler setter functions that assign an arbitrary handler
without an obvious allowlist / validation guard in the same function body.
"""

from __future__ import annotations

import re

from _util import body_text_nocomment, fn_body, fn_name, function_items, is_pub, line_col, snippet_of

_FN_NAME_RE = re.compile(r"(?i)^set[_]?fallback[_]?handler$")
_ASSIGN_RE = re.compile(
    r"(?i)(fallback_handler\s*=\s*Some\s*\(\s*handler\s*\)|"
    r"fallbackHandler\s*=\s*(?:handler|newHandler))"
)
_GUARD_RE = re.compile(
    r"(?i)(allowed_handlers\s*\.\s*contains\s*\(\s*&?\s*handler\s*\)|"
    r"allowed_fallback_handlers|"
    r"is_allowed_fallback\s*\(\s*handler\s*\)|"
    r"whitelist|allowlist|"
    r"code_hash|extcodehash|"
    r"assert\w*\s*!\s*\(\s*[^)]*handler[^)]*(?:contains|==)|"
    r"require\s*\(\s*[^)]*handler[^)]*(?:contains|==)|"
    r"panic!\s*\(|revert\s*\()"
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if not is_pub(fn, source):
            continue
        if not _FN_NAME_RE.search(fn_name(fn, source)):
            continue
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        if not _ASSIGN_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"{filepath}: public fallback-handler setter assigns an arbitrary handler "
                "without an obvious allowlist / validation guard "
                "(setfallbackhandler_bypass_hijacks_rented_erc721_1155)."
            ),
        })
    return hits
