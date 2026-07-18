"""
r94_loop_signature_not_bound_to_target_consumer.py

Flags approve-by-signature fns that build a signed digest from
(calls, signer) but omit the target consumer contract address —
signature approved for consumer A is reusable on consumer B.

Source: Solodit #36855 (OpenZeppelin Ironblocks ApprovedCallsPolicy).
Class: signature-not-bound-to-target-consumer (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(approve_with_signature|approve_by_sig|authorize_calls|"
    r"pre_approve_calls|submit_approval_sig)"
)
_DIGEST_BUILD_RE = re.compile(
    r"(keccak256|sha256|hash)\s*\(\s*(abi::encode|&\(|\(|\[)"
)
_TARGET_BOUND_RE = re.compile(
    r"(target_consumer|consumer_address|dest_contract|target\s*,|msg\.sender|"
    r"address\(this\)|env\.current_contract_address|chain_id\s*,)"
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
        if not _DIGEST_BUILD_RE.search(body_nc):
            continue
        if _TARGET_BOUND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` builds a signature digest without "
                f"binding the target consumer / current contract "
                f"address — signature is replayable on a sibling "
                f"consumer (signature-not-bound-to-target-consumer). "
                f"See Solodit #36855 (Ironblocks Firewall)."
            ),
        })
    return hits
