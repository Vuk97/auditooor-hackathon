"""
r94_loop_merkle_leaf_no_used_flag.py

Flags redeem/claim fns that verify a Merkle proof over a leaf but
never record / check a `used[leaf]` set — same proof replays until
pool drained.

Source: Solodit #36240 (Beanstalk redeemDepositsAndInternalBalances).
Class: merkle-leaf-no-used-flag (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(redeem|claim|withdraw_with_proof|merkle_claim|airdrop_claim|"
    r"redeem_deposits|batch_redeem)"
)
_VERIFY_PROOF_RE = re.compile(
    r"merkle_proof\.verify|MerkleProof\.verify|verify_proof\s*\(|"
    r"verify_merkle\s*\(|is_valid_merkle_proof"
)
_USED_FLAG_RE = re.compile(
    fr"(used_leaves|used_leaf|consumed_leaf|claimed_leaves|"
    fr"leaf_consumed|claimed_map|redeemed_map|claimed_bitmap|"
    fr"self\.used|self\.claimed)\s*(\[|\.|\.insert|\.set)|"
    fr"(used|claimed|redeemed)\s*\.\s*insert\s*\(\s*{IDENT}leaf|"
    fr"\.get\s*\(\s*&?\s*{IDENT}leaf\s*\)"
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
        if not _VERIFY_PROOF_RE.search(body_nc):
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
                f"pub fn `{name}` verifies a Merkle proof but never "
                f"marks the leaf as used — attacker replays identical "
                f"parameters until pool drained (merkle-leaf-no-used-"
                f"flag). See Solodit #36240 (Beanstalk Finale)."
            ),
        })
    return hits
