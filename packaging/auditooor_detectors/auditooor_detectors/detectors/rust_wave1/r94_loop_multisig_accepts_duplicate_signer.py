"""
r94_loop_multisig_accepts_duplicate_signer.py

Flags validate-multisig / verify-message fns that iterate over
supplied signatures, recover the signer, check "is attestor", and
accumulate counter — without dedup-by-signer.

Source: Solodit #63314 (Pashov SXT SubstrateSignatureValidator).
Class: multisig-accepts-duplicate-signer (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(validate_message|verify_multisig|check_signatures|verify_threshold|validate_attestors)")
_LOOP_AND_COUNT_RE = re.compile(
    fr"(for\s+\w+\s+in\s+{IDENT}(sigs|signatures))|"
    fr"(loop\s*\{{[\s\S]{{0,300}}?(count|acquired_threshold)\s*[+]=)|"
    fr"(\w+\.iter\s*\(\s*\)\.\s*for_each|(count|acquired_threshold|quorum_count)\s*\+=\s*1)"
)
_DEDUP_RE = re.compile(
    r"(seen_signers|signer_set\.insert|signers_seen|dedup|HashSet::new|"
    r"require\s*!\s*seen|assert\s*!\s*signers_seen|signer_used)"
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
        if not _LOOP_AND_COUNT_RE.search(body_nc):
            continue
        if _DEDUP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` accumulates threshold across "
                f"supplied signatures without dedup-by-signer — "
                f"same signer's sig counted N times, threshold "
                f"bypass (multisig-accepts-duplicate-signer). See "
                f"Solodit #63314 (SXT SubstrateSignatureValidator)."
            ),
        })
    return hits
