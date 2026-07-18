"""
r94_loop_ecrecover_null_address_not_rejected.py

Flags fns that call ecrecover / secp256k1_recover and USE the result
(compare, assign, authorize) WITHOUT checking that it isn't the
null / zero address.

Source: Solodit #48885 (TrailOfBits Polkaswap bridge).
Class: ecrecover-null-address-not-rejected (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(verify_sig|recover_signer|validate_sig|is_authorized|is_valid_sig|check_sig)")
_RECOVER_CALL_RE = re.compile(
    r"(ecrecover|secp256k1_recover|ECDSA::recover|ECDSA\.recover|recover_address)\s*\("
)
_NULL_CHECK_RE = re.compile(
    fr"(!=\s*address\(0\)|!=\s*0x0|!=\s*AddressZero|is_zero\s*\(\s*\)\s*==\s*false|"
    fr"require\s*\(\s*{IDENT}signer\s*!=\s*(address\(0\)|0\b)|"
    fr"assert[!_]?\s*\(\s*{IDENT}signer\s*!=\s*0\b|"
    fr"{IDENT}signer\s*!=\s*0\b)"
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
        if _NULL_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls ecrecover / secp256k1_recover "
                f"and uses result without a null-address check — "
                f"invalid sig returns 0, attacker may pass zero-"
                f"signature (ecrecover-null-address-not-rejected). "
                f"See Solodit #48885 (Polkaswap bridge)."
            ),
        })
    return hits
