"""
r94_loop_ecrecover_malleability_no_check.py

Flags `recoverSigner` / similar fns that call `ecrecover` or
equivalent without a bound check on the `s` component of the signature
(to reject non-canonical high-S signatures).

Source: Solodit #60156 (Quantstamp Hinkal Protocol).
Class: ecrecover-malleability-no-check (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(recover_signer|recoverSigner|ecrecover|verify_sig|verify_signature)")
_ECRECOVER_RE = re.compile(
    r"ecrecover\s*\(|secp256k1::recover|secp256k1_recover|"
    r"k256::.*?recover|Secp256k1::verify"
)
_S_BOUND_RE = re.compile(
    r"s\s*<=\s*(0x7fffffffffffffffffffffffffffffff|HALF_ORDER|"
    r"secp256k1n\s*/\s*2|SECP256K1_HALF_N)|"
    r"require!?\s*\([^)]*s\s*<=|assert!?\s*\([^)]*s\s*<=|"
    r"is_low_s|check_low_s|normalize_s|ECDSA\.recover"
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
        if not _ECRECOVER_RE.search(body_nc):
            continue
        if _S_BOUND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls ecrecover / secp256k1 recover "
                f"without an `s <= HALF_ORDER` check or OpenZeppelin "
                f"ECDSA.recover wrapper. Signature-malleability — (s, r) "
                f"and (-s, r) both accepted. See Solodit #60156 (Hinkal)."
            ),
        })
    return hits
