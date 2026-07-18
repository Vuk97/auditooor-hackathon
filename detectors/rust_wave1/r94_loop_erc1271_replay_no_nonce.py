"""
r94_loop_erc1271_replay_no_nonce.py

Flags ERC-1271-style is_valid_signature fns that verify a signature
over a hash without reading / writing a per-owner nonce or `used`
mapping — same signature replays across operations.

Source: Solodit #56710 (OpenZeppelin SSO ERC1271Handler).
Class: erc1271-replay-no-nonce (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(is_valid_signature|isValidSignature|validate_signature|verify_sig1271)")
_RECOVER_RE = re.compile(
    r"\.recover\s*\(|ecrecover\s*\(|secp256k1_recover\s*\(|"
    fr"recover_signer\s*\(|env\.crypto\.{IDENT}recover"
)
_NONCE_TRACK_RE = re.compile(
    r"(used_sigs|used_hashes|used\[|consumed_sig|nonce|\.increment\s*\(\s*nonce|"
    r"sig_nonces|nonces_of|hash_used)"
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
        if not _RECOVER_RE.search(body_nc):
            continue
        if _NONCE_TRACK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` ERC-1271 verification recovers signer "
                f"but never checks/bumps a nonce / used-hash map — "
                f"identical signature replays (erc1271-replay-no-nonce). "
                f"See Solodit #56710 (OpenZeppelin SSO)."
            ),
        })
    return hits
