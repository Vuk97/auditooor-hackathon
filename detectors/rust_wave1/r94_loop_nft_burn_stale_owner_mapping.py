"""
r94_loop_nft_burn_stale_owner_mapping.py

Flags NFT burn fns that read `owner_of(id)` / `nft_owners[id]` /
`sr.owner` for authorization but DO NOT also check that the current
caller still matches the ERC721-level owner (i.e., the two
mappings can be out of sync).

Source: Solodit #27455 (Codehawks DittoETH LibShortRecord).
Class: nft-burn-stale-owner-mapping (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(burn_\w+|burn_short_record|burn_nft|destroy_\w+)")
_SHADOW_OWNER_READ_RE = re.compile(
    r"(sr\.owner|short_record\.owner|nft_owners\s*\[|shadow_owner|internal_owner_of)"
)
_ERC721_OWNER_READ_RE = re.compile(
    r"(IERC721\.ownerOf|erc721\.owner_of|nft\.owner_of\s*\(|erc721_owner_of)"
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
        if not _SHADOW_OWNER_READ_RE.search(body_nc):
            continue
        if _ERC721_OWNER_READ_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads a shadow/internal owner "
                f"mapping (sr.owner / nft_owners[id]) for burn auth "
                f"without cross-checking the ERC721 ownerOf — stale "
                f"mapping lets previous owner burn new owner's NFT "
                f"(nft-burn-stale-owner-mapping). See Solodit #27455 "
                f"(DittoETH)."
            ),
        })
    return hits
