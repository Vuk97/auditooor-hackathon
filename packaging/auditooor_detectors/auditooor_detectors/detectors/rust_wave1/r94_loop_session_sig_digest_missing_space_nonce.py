"""
r94_loop_session_sig_digest_missing_space_nonce.py

Flags session-signature hasher fns that include `calls` and
`session_id` in the digest but OMIT `space` / `nonce` / `chain_id`
— attacker can replay the session signature on a different branch
or in a partial-frontrun scenario.

Source: Solodit #63761 (C4 Sequence SessionSig).
Class: session-sig-digest-missing-space-nonce (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(session_digest|session_hash|hash_session_call|build_session_digest)")
_HASH_BUILD_RE = re.compile(
    r"(keccak256|sha256|hash)\s*\(\s*(abi::encode|abi\.encode|&\(|\[)"
)
_INCLUDES_SPACE_NONCE_RE = re.compile(
    r"\b(space|nonce|chain_id|block\.chainid)\s*,|"
    r",\s*(space|nonce|chain_id|block\.chainid)\b"
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
        if not _HASH_BUILD_RE.search(body_nc):
            continue
        if _INCLUDES_SPACE_NONCE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` builds session-sig digest without "
                f"including space/nonce/chain_id — session can be "
                f"replayed on a different branch (session-sig-digest-"
                f"missing-space-nonce). See Solodit #63761 (Sequence)."
            ),
        })
    return hits
