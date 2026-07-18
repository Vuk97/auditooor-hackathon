"""
r94_loop_nft_collection_verified_bypass.py

Flags NFT staking/accepting fns that read `nft_metadata.collection.key`
to compare against a whitelisted collection address but NEVER check
`collection.verified == true`. An unverified spoof collection passes.

Source: Solodit #54947 (OtterSec Claynosaurz).
Class: nft-collection-verified-bypass (both).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(r"(?i)(stake|accept|deposit_nft|register_nft|mint_nft|lock_nft)")

_COLLECTION_KEY_RE = re.compile(
    r"\.collection\.key\s*==|collection\.key\s*==|nft_metadata\.collection"
)

_VERIFIED_CHECK_RE = re.compile(
    r"\.collection\.verified|collection\.verified\s*(==|!=)|"
    r"require!?\s*\([^)]*\.verified|assert!?\s*\([^)]*\.verified|"
    r"is_verified\s*\("
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

        if not _COLLECTION_KEY_RE.search(body_nc):
            continue
        if _VERIFIED_CHECK_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` checks `nft_metadata.collection.key` "
                f"against a whitelist but never asserts "
                f"`collection.verified == true`. Spoofed unverified "
                f"collection passes the check. See Solodit #54947 "
                f"(Claynosaurz)."
            ),
        })
    return hits
