"""
r94_loop_bridge_execute_calldata_missing_chainid_replay.py

Flags bridge `execute` / `process_message` fns that compute a
tx-deduplication hash from `(id, origin_domain, dest_domain)` but
OMIT `chain_id` — attacker replays same calldata on a second
chain deployment.

Source: Solodit #25135 (C4 Connext BridgeFacet).
Class: bridge-execute-calldata-missing-chainid-replay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(bridge_execute|xcall_execute|process_message|finalize_xcall|deliver_message)")
_HASH_BUILD_RE = re.compile(
    r"(keccak256|sha256|hash)\s*\(\s*(abi::encode|abi\.encode|&\(|\[)"
)
_INCLUDES_CHAINID_RE = re.compile(
    r"\b(chain_id|chainId|block\.chainid)\b"
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
        if not _HASH_BUILD_RE.search(body_nc):
            continue
        if _INCLUDES_CHAINID_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` hashes bridge tx dedup key without "
                f"chain_id — attacker replays same calldata on a "
                f"second chain deployment (bridge-execute-calldata-"
                f"missing-chainid-replay). See Solodit #25135 "
                f"(Connext BridgeFacet)."
            ),
        })
    return hits
