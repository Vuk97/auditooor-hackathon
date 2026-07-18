"""
r94_loop_ecdsa_recover_zero_address_validation_bypass.py

Flags sig-validation fns that use `ecrecover` / `ECDSA.recover` /
`secp256k1_recover` to derive a signer and compare it against an
owner/authority field, without first asserting the recovered address
is non-zero — ECDSA.recover returns 0 for malformed sigs, so if the
owner slot is ever zero any bogus signature validates.

Source: Solodit #53328 (Pashov Omo 2025-01-25).
Class: ecdsa-recover-zero-address-validation-bypass (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(_validate_signature|validate_signature|"
    r"is_valid_signature|verify_signature|verify_sig|"
    r"check_signature|recover_signer)"
)
_RECOVER_RE = re.compile(
    r"(?i)(ECDSA\s*::\s*recover|ecdsa_recover|ecrecover|"
    r"secp256k1_recover|k256::.*recover|"
    r"\.\s*recover_eth\w*\s*\(|\.\s*recover\s*\()"
)
_ZERO_CHECK_RE = re.compile(
    fr"(?i)(signer\s*!=\s*address\s*\(\s*0|recovered\s*!=\s*address\s*\(\s*0|"
    fr"signer\s*!=\s*Address::zero|signer\s*\.\s*is_zero\s*\(\s*\)\s*==\s*false|"
    fr"!\s*{IDENT}signer\s*\.\s*is_zero|require\s*\(\s*{IDENT}signer\s*!=\s*address\(0\)|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}signer\s*!=\s*{IDENT}zero|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}signer\s*!=\s*\[\s*0[_uU]?\w*\s*;\s*20\s*\]|"
    fr"{IDENT}signer\s*!=\s*\[\s*0[_uU]?\w*\s*;\s*20\s*\])"
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
        if _ZERO_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` uses ECDSA recover without checking "
                f"the recovered signer != address(0) — malformed sigs "
                f"recover to zero, so if the owner slot is ever zero "
                f"any bogus signature validates "
                f"(ecdsa-recover-zero-address-validation-bypass). "
                f"See Solodit #53328 (Pashov Omo 2025-01-25)."
            ),
        })
    return hits
