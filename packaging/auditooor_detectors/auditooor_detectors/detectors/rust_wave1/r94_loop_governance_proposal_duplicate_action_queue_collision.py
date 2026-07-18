"""
r94_loop_governance_proposal_duplicate_action_queue_collision.py

Flags governor queue fns that hash (target, value, signature, data)
into a uniqueness map WITHOUT including the proposal-id / action
index — duplicate identical actions collide, second queue() reverts,
entire proposal is DoS'd.

Source: Solodit #11543 (Compound GovernorAlpha).
Class: governance-proposal-duplicate-action-queue-collision (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(queue_transaction|queue_proposal|queue_action|enqueue_tx)")
_HASH_COLLISION_RE = re.compile(
    fr"(queued_transactions|queued_txs|queued_actions)\s*\.(get|contains|set|insert)\s*\(\s*\w+\)|"
    fr"queued_transactions\s*\[\s*(tx_hash|action_hash|hash)\s*\]|"
    fr"hash\s*=\s*keccak256\s*\(\s*abi::encode\s*\(\s*target\s*,\s*value\s*,\s*signature\s*,\s*data\s*\)\s*\)|"
    fr"let\s+{IDENT}hash\s*=\s*hash\s*\(\s*&?\(\s*target\s*,\s*value\s*,\s*signature\s*,\s*data\s*\)\s*\)"
)
_INCLUDES_PROP_ID_RE = re.compile(
    r"proposal_id\s*,\s*(target|value|signature|data)|"
    r"(target|value|signature|data)\s*,\s*proposal_id|"
    r"action_index|eta\s*,\s*proposal_id|idx\s*,\s*target"
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
        if not _HASH_COLLISION_RE.search(body_nc):
            continue
        if _INCLUDES_PROP_ID_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` hashes (target, value, signature, "
                f"data) into queue uniqueness map without proposal_id "
                f"/ action_index — duplicate actions collide and DoS "
                f"the whole proposal (governance-proposal-duplicate-"
                f"action-queue-collision). See Solodit #11543 "
                f"(Compound GovernorAlpha)."
            ),
        })
    return hits
