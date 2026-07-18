"""
r94_loop_multisig_threshold_signature_reuse_no_dedup.py

Flags multisig verify fns that accumulate `acquired_threshold`
per-signature but don't dedup the incoming SIGNATURE ARRAY —
duplicate bytes accepted even if they recover the same signer.

Distinct from 'multisig-accepts-duplicate-signer': that class is
about signers; this one is about multisig-exec fns where the loop
iterates raw sigs bytes and the dedup is expected on BYTES (or on
signature hash), not the signer.

Source: Solodit #53387 (TrailOfBits Franklin Templeton).
Class: multisig-threshold-signature-reuse-no-dedup (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(signed_data_execution|exec_with_sigs|multisig_exec|verify_threshold|execute_signed)")
_ACC_LOOP_RE = re.compile(
    r"(acquired_threshold|quorum|threshold_count|sig_count)\s*(?:\+=|\+ =\s*1)",
)
_DEDUP_RE = re.compile(
    r"(seen_sig|sig_hashes_seen|prev_sig|dedup_sigs|processed_sig|"
    r"unique_sig_hashes|HashSet::new\s*\(\s*\))"
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
        if not _ACC_LOOP_RE.search(body_nc):
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
                f"pub fn `{name}` loops over supplied sigs and "
                f"increments acquired_threshold without deduping "
                f"sig bytes / hashes — attacker submits N identical "
                f"copies of one valid sig to hit threshold "
                f"(multisig-threshold-signature-reuse-no-dedup). "
                f"See Solodit #53387 (Franklin Templeton)."
            ),
        })
    return hits
