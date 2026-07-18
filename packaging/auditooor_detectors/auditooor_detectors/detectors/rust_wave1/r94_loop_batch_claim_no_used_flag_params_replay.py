"""
r94_loop_batch_claim_no_used_flag_params_replay.py

Flags batch-claim / redeem-batch fns that consume a merkle proof or
params bundle without recording successfully-used bundles — same
params can be re-redeemed indefinitely.

Source: Solodit #36240 (Codehawks Beanstalk Finale).
Class: batch-claim-no-used-flag-params-replay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(redeem_deposits_and_internal_balances|"
    r"redeemBatch|batch_claim|batchClaim|"
    r"claim_batch|execute_batch_claim|"
    r"redeem_internal_balances)"
)
_MERKLE_OR_PROOF_RE = re.compile(
    r"(?i)(verify_proof|verifyProof|"
    r"merkle_proof|merkleProof|"
    r"params\s*\.\s*claim|claim_params|"
    r"params_hash|batch_proof)"
)
_USED_FLAG_RE = re.compile(
    fr"(?i)(used\s*\[\s*{IDENT}(hash|params|id)\s*\]\s*=\s*true|"
    fr"claimed\s*\[\s*{IDENT}leaf\s*\]\s*=\s*true|"
    fr"used_params\.insert|processed_batches\.insert|"
    fr"claimed_params\s*\[|is_consumed|mark_consumed|"
    fr"usedRoots\[)"
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
        if not _MERKLE_OR_PROOF_RE.search(body_nc):
            continue
        if _USED_FLAG_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} accepts a merkle proof / params "
                f"bundle without recording successfully-used "
                f"bundles — same params can be re-redeemed "
                f"indefinitely (batch-claim-no-used-flag-params-replay). "
                f"See Solodit #36240 (Codehawks Beanstalk Finale)."
            ),
        })
    return hits
