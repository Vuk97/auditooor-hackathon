"""
r94_loop_zk_expired_cert_accepted.py

Flags zkVM attestation/verify fns that ingest caller-supplied cert or
CRL hashes as public inputs, but do NOT check the cert's expiry /
validity window against current time.

Source: Solodit #53370 (TOB Automata DCAP attestation RISC0/SP1).
Class: zk-expired-cert-accepted (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(verify_?quote|verify_?attestation|verify_?dcap|verify_?sgx|verify_?proof)")

_CERT_CTX_RE = re.compile(
    r"cert_hash|crl_hash|x509|certificate|x5c|issuer|\.cert\.|"
    r"risc0|sp1|zkvm|groth16|plonk"
)

_EXPIRY_CHECK_RE = re.compile(
    r"not_after|valid_until|expires_at|expiration|notAfter|"
    fr"block_timestamp\s*<=?\s*{IDENT}expir|now\s*<=?\s*{IDENT}expir|"
    r"require!?\s*\([^)]*(valid_until|not_after|expir)|"
    r"cert\.is_valid_at|check_cert_validity"
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
        if not _CERT_CTX_RE.search(body_nc):
            continue
        if _EXPIRY_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` verifies a zkVM attestation/quote that "
                f"references certs/CRLs but doesn't check cert validity "
                f"window (not_after / valid_until / expires_at) against "
                f"current time. Expired certs pass verification. See "
                f"Solodit #53370 (Automata DCAP)."
            ),
        })
    return hits
