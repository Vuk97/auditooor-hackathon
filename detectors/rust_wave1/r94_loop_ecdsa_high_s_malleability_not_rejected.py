"""
r94_loop_ecdsa_high_s_malleability_not_rejected.py

Flags signature-verification fns that call ECDSA recover (ecrecover /
secp256k1::recover) without rejecting high-S signatures (S > n/2) —
EIP-2 rejects these for malleability; the high-S variant slips past
used-sig trackers that only log the normalized form.

Source: Solodit #21369 (Spearbit Polygon zkEVM).
Class: ecdsa-high-s-malleability-not-rejected (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(verify_signature|verifySignature|process_tx|processTx|"
    r"recover_signer|recoverSigner|ecrecover_safe|_verify_sig|check_sig)"
)
_ECDSA_CALL_RE = re.compile(
    r"(ecrecover\s*\(|ecdsa::recover|secp256k1::recover|"
    r"ECDSA\.recover|\.recover_eth|k256::ecdsa|"
    r"\bcrypto_ecdsa_secp256k1_recover)"
)
_HIGH_S_CHECK_RE = re.compile(
    fr"(s\s*>\s*{IDENT}SECP256K1N_HALF|s\s*>=\s*{IDENT}SECP256K1N_HALF|"
    fr"s\s*>\s*secp256k1n_half|{IDENT}s_value\s*<=\s*{IDENT}N_OVER_2|"
    fr"require\s*\(\s*{IDENT}(s|sValue)\s*<=\s*{IDENT}HALF|"
    fr"check_low_s|lowS|canonical_signature|"
    fr"require\s*\(\s*uint256\s*\(\s*s\s*\)\s*<=\s*{IDENT}0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0|"
    fr"EIP\w*2\s+malleability|hash_to_field_signed_curve)"
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
        if not _ECDSA_CALL_RE.search(body_nc):
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
                f"pub fn `{name}` calls ECDSA recover without rejecting "
                f"high-S signatures (S > n/2) — EIP-2 rejects these for "
                f"malleability; high-S variant slips past used-sig trackers "
                f"that only log the normalized form "
                f"(ecdsa-high-s-malleability-not-rejected). "
                f"See Solodit #21369 (Spearbit Polygon zkEVM)."
            ),
        })
    return hits
