"""
r94_loop_vulnerable_ecdsa_library_eip2098_malleable_version.py

Flags fns that call the 2-arg form `ECDSA.recover(hash, signature)` from
OpenZeppelin ECDSA <4.7.3, which accepts EIP-2098 compact signatures and
is therefore vulnerable to signature malleability. Safe forms are the
explicit 4-arg `ECDSA.recover(hash, v, r, s)` / `ECDSA.tryRecover(...)`
or pinning OZ >=4.7.3 / using solady.

Source: Solodit #50225 (Halborn Biconomy Smart Wallet V2).
Class: vulnerable-ecdsa-library-eip2098-malleable-version (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(recover_signer|recoverSigner|verify|"
    r"verify_signature|validate_user_op|"
    r"isValidSignature|_validateSignature)"
)
_VULN_2ARG_RE = re.compile(
    r"(ECDSA\.recover\s*\(\s*&?\w+\s*,\s*&?\w+\s*\)\s*|"
    r"ECDSA\s*::\s*recover\s*\(\s*&?\w+\s*,\s*&?\w+\s*\))"
)
_SAFE_FORM_RE = re.compile(
    r"(ECDSA\.recover\s*\(\s*\w+\s*,\s*v\s*,\s*r\s*,\s*s\s*\)|"
    r"ECDSA\.tryRecover\s*\(\s*\w+\s*,\s*v\s*,\s*r\s*,\s*s\s*\)|"
    r"openzeppelin-contracts\s*=\s*\"\s*\^?\s*4\.7\.[3-9]|"
    r"openzeppelin-contracts\s*=\s*\"\s*\^?\s*(4\.8|4\.9|5\.|[5-9]\.)|"
    r"solady\s*=|ECDSA\w+Cached)"
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
        if not _VULN_2ARG_RE.search(body_nc):
            continue
        if _SAFE_FORM_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} calls ECDSA.recover(hash, signature) "
                f"— 2-arg form from OpenZeppelin ECDSA <4.7.3 is "
                f"vulnerable to EIP-2098 compact-signature malleability "
                f"(vulnerable-ecdsa-library-eip2098-malleable-version). "
                f"See Solodit #50225 (Halborn Biconomy Smart Wallet V2)."
            ),
        })
    return hits
