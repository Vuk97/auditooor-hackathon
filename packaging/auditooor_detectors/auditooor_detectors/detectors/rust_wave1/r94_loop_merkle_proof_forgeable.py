"""
r94_loop_merkle_proof_forgeable.py

Flags Merkle-proof verifiers that do NOT enforce a fixed leaf-layer
(depth-prefix / domain-separator tag) between hash nodes, letting an
attacker present an intermediate node as a leaf.

Source: Solodit #43784 (TOB Orga/Merk).
Class: merkle-proof-forgeable (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(verify_?proof|verify_?merkle|check_?inclusion|prove_?inclusion|verify_?inclusion)")
_HASH_NODE_RE = re.compile(
    r"hasher\.finalize|keccak256\s*\(|sha256\s*\(|blake2b\s*\(|hash::hashv"
)
_DOMAIN_TAG_RE = re.compile(
    r"LEAF_TAG|NODE_TAG|\\x00|\\x01|0x00,|0x01,|"
    r"domain_separator|leaf_prefix|node_prefix|"
    r"\b0u8\b\s*,|\b1u8\b\s*,"
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
        if not _HASH_NODE_RE.search(body_nc):
            continue
        if _DOMAIN_TAG_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` verifies a Merkle proof via hashers "
                f"without a leaf/node domain-tag prefix (0x00/0x01 byte "
                f"or LEAF_TAG/NODE_TAG constant). Attacker presents an "
                f"intermediate node as a leaf → forged inclusion. See "
                f"Solodit #43784 (Orga/Merk)."
            ),
        })
    return hits
