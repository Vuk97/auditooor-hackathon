"""
r94_loop_aa_userop_hash_missing_entrypoint_replay.py

Flags EIP-4337 userOpHash / getUserOpHash fns that compute the
signed-over hash without binding both `entryPoint` and `chainId`.
Missing either enables replay across EntryPoint deployments (same
chain) or across chains.

Source: Solodit #55601 (Cyfrin Metamask DelegationFramework).
Class: aa-userop-hash-missing-entrypoint-replay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(get_user_op_hash|compute_user_op_hash|"
    r"user_operation_hash|hash_user_op|userop_hash|"
    r"get_op_hash|compute_op_hash)"
)
# Must see *hashing* of userop fields.
_HASH_RE = re.compile(
    r"(?i)(keccak\w*\s*\(|sha256\s*\(|poseidon\s*\(|"
    fr"hash_{IDENT}struct|abi_encode|\.\s*encode\s*\(|"
    r"to_bytes\s*\(|serialize\s*\()"
)
_ENTRYPOINT_RE = re.compile(
    r"(?i)(entry_?point|\bENTRY_POINT\b|entrypoint_addr|"
    r"entrypoint_address|self\.entry_point)"
)
_CHAINID_RE = re.compile(
    r"(?i)(chain_?id|block\.chainid|env\.chain_id|"
    r"self\.chain_id|CHAIN_ID)"
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
        if not _HASH_RE.search(body_nc):
            continue
        has_ep = bool(_ENTRYPOINT_RE.search(body_nc))
        has_cid = bool(_CHAINID_RE.search(body_nc))
        if has_ep and has_cid:
            continue
        missing = []
        if not has_ep:
            missing.append("entryPoint")
        if not has_cid:
            missing.append("chainId")
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` builds the EIP-4337 userOpHash "
                f"without binding {' + '.join(missing)} — userOp "
                f"replayable across EntryPoint deployments / chains "
                f"(aa-userop-hash-missing-entrypoint-replay). "
                f"See Solodit #55601 (Cyfrin Metamask DelegationFramework)."
            ),
        })
    return hits
