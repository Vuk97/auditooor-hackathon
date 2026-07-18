"""
r94_loop_compact_sig_variant_allows_replay.py

Flags ECDSA-recover fns that accept BOTH 65-byte and EIP-2098
(64-byte compact) signature formats — the same semantic signature
has two distinct byte-encodings and bypasses sig-hash nonce maps.

Source: Solodit #50225 (Halborn Biconomy Smart Wallet V2).
Class: compact-sig-variant-allows-replay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(recover|try_recover|verify_sig|validate_sig|check_sig)")
_TWO_LENGTH_RE = re.compile(
    r"sig\.len\s*\(\s*\)\s*==\s*64\s*\|\|\s*sig\.len\s*\(\s*\)\s*==\s*65|"
    r"signature\.length\s*==\s*64\s*\|\|\s*signature\.length\s*==\s*65|"
    r"if\s+len\s*==\s*64\s*\{[\s\S]*?\}\s*else\s+if\s+len\s*==\s*65|"
    r"len\s*==\s*64\s*\{\s*(?:.|\n){0,300}?\}\s*else\s+if\s+len\s*==\s*65|"
    r"(compact|eip2098|eip_2098)"
)
_SAFE_NORMALIZE_RE = re.compile(
    r"normalize_compact_sig|canonicalize_signature|only_65_byte|reject_compact|"
    r"signature\.length\s*!=\s*65.*revert"
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
        if not _TWO_LENGTH_RE.search(body_nc):
            continue
        if _SAFE_NORMALIZE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` accepts both 65-byte and EIP-2098 "
                f"compact signature formats — same semantic signature "
                f"has two byte-encodings, bypasses sig-hash-keyed "
                f"nonce map (compact-sig-variant-allows-replay). "
                f"See Solodit #50225 (Biconomy Smart Wallet V2)."
            ),
        })
    return hits
