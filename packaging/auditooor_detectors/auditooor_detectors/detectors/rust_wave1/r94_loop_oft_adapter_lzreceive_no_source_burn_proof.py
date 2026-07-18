"""
r94_loop_oft_adapter_lzreceive_no_source_burn_proof.py

Flags cross-chain OFT / LayerZero adapter receiver fns (lz_receive,
oft_receive, credit_to) that release adapter inventory purely on
DVN/bridge attestation, without independently verifying that the
source-chain burn/debit actually occurred (light-client proof,
source-nonce echo, merkle-proof-of-burn).

Source: Kelp rsETH $220M exploit (2026-04-18).
Class: oft-adapter-lzreceive-no-source-burn-proof (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(lz_receive|lzReceive|_lz_receive|_lzReceive|"
    r"oft_receive|receive_oft|credit_to|_credit_to)"
)
_INVENTORY_RELEASE_RE = re.compile(
    r"(safe_transfer\s*\(|safeTransfer\s*\(|"
    r"token\.transfer\s*\(|underlying\.transfer\s*\(|"
    r"adapter_balance\s*-=|inventory\s*-=|"
    fr"balance_of\s*\(\s*{IDENT}self|"
    r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\))"
)
_SOURCE_PROOF_RE = re.compile(
    r"(light_client_verify|lightClientVerify|"
    r"verify_source_burn|verifySourceBurn|"
    r"source_nonce_echo|sourceNonceEcho|"
    r"merkle_proof_of_burn|merkleProofOfBurn|"
    r"proof_of_burn|proofOfBurn|"
    r"verify_source_state|ismVerify|ism\.verify|"
    r"merkle_root_from_source|attested_source_burn|"
    r"assert_source_state_root)"
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
        if not _INVENTORY_RELEASE_RE.search(body_nc):
            continue
        if _SOURCE_PROOF_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} is a cross-chain receiver that "
                f"releases inventory purely on DVN/bridge attestation, "
                f"without independent proof that the source-chain burn "
                f"actually occurred (light-client proof, source-nonce "
                f"echo, merkle proof of burn) "
                f"(oft-adapter-lzreceive-no-source-burn-proof). "
                f"Kelp rsETH $220M exploit 2026-04-18."
            ),
        })
    return hits
