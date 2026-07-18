"""
r94_loop_cointype_wrap_unvalidated.py

Flags Aptos / Wormhole wrap fns that derive the wrapped-asset mint
identifier from VAA-supplied origin data without verifying that the
origin-cointype matches the registered whitelist.

Class: cointype-wrap-unvalidated (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(wrap|create_wrapped|register_wrapped|attest_token|deploy_wrapped)")
_VAA_ORIGIN_RE = re.compile(
    r"vaa\.origin|vaa\.token_address|origin_chain|origin_address|"
    r"wrapped_asset|cointype|coin_type"
)
_VALIDATION_RE = re.compile(
    r"whitelist|is_allowed|registered_cointypes|"
    r"assert_eq!?\s*\([^)]*cointype|require!?\s*\([^)]*cointype|"
    r"check_cointype|validate_cointype|"
    r"allow_list\.contains|registry\.get"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _VAA_ORIGIN_RE.search(body_nc):
            continue
        if _VALIDATION_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` derives a wrapped-asset identity from "
                f"VAA origin data (origin_chain/origin_address/cointype) "
                f"without validating against a whitelist/registry. "
                f"Attacker VAA forges arbitrary wrapped assets."
            ),
        })
    return hits
