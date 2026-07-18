"""
r94_loop_ecrecover_high_s_value_not_rejected.py

Flags ecrecover / secp256k1_recover consumers that don't bound-check
the `s` value against SECP256K1_N/2 (high-s malleability) —
alternative platforms return a valid signer for the "other half"
signature, producing two+ valid sigs for same message.

Source: Solodit #45173 (Kakarot) + general malleability.
Class: ecrecover-high-s-value-not-rejected (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(verify_sig|recover_signer|validate_sig|is_valid_sig|check_sig)")
_RECOVER_CALL_RE = re.compile(
    r"(ecrecover|secp256k1_recover|ECDSA::recover)\s*\("
)
_HIGH_S_CHECK_RE = re.compile(
    fr"(s\s*>\s*SECP256K1_N_HALF|s\s*>\s*HALF_CURVE_ORDER|"
    fr"(require|assert)\s*\(\s*{IDENT}s\s*<=\s*0x7fffffffffffffffffffffffffffffff|"
    fr"s\s*<=\s*SECP256K1_N_DIV_2|"
    fr"ECDSA\.tryRecover|ECDSA::tryRecover|OZ_ECDSA_tryRecover|tryRecover)"
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
        if not _RECOVER_CALL_RE.search(body_nc):
            continue
        if _HIGH_S_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls ecrecover / secp256k1_recover "
                f"without a high-s bound check — malleable signature "
                f"produces a second valid sig for the same message "
                f"(ecrecover-high-s-value-not-rejected). See Solodit "
                f"#45173 (Kakarot)."
            ),
        })
    return hits
