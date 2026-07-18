"""
r94_loop_bitcoin_sighash_confusion.py

Flags BTC tx-signing fns that call sighash with a witness commitment
computed inconsistently: `CalcWitnessSigHashV0` with non-witness
PKScript, or vice-versa.

Source: Solodit #58673 (Sherlock ZetaChain BTC observer).
Class: bitcoin-sighash-confusion (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(sign_?btc|sign_?tx|compute_?sighash|witness_?sighash)")
_SIGHASH_CALL_RE = re.compile(
    r"CalcWitnessSigHashV\d|calc_witness_sighash|"
    r"CalcSignatureHash|compute_sighash_v0|txscript\.CalcSignatureHash|"
    r"secp256k1\.sign\s*\(|sighash_type"
)
_WITNESS_MISMATCH_RE = re.compile(
    r"CalcWitnessSigHash[^(]*\([^)]*non_witness|"
    r"CalcSignatureHash[^(]*\([^)]*witness_program|"
    # Or: BOTH sighash variants used in one fn body (rare but possible)
    r"CalcWitnessSigHash[\s\S]*CalcSignatureHash|"
    r"CalcSignatureHash[\s\S]*CalcWitnessSigHash"
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
        if not _SIGHASH_CALL_RE.search(body_nc):
            continue
        # If a fn has multiple witness/legacy sighash call variants mixed → flag
        witness_count = len(re.findall(r"CalcWitnessSigHash", body_nc))
        legacy_count = len(re.findall(r"CalcSignatureHash", body_nc))
        if witness_count and legacy_count:
            line, col = line_col(fn)
            hits.append({
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` uses both CalcWitnessSigHash* and "
                    f"CalcSignatureHash* in the same sign-path. BTC "
                    f"witness-commitment confusion — network may reject "
                    f"signed txs. See Solodit #58673 (ZetaChain)."
                ),
            })
    return hits
