"""
bridge_validator_set_hash_not_domain_separated.py

Flags Rust bridge or consensus functions that hash or verify a validator
set checkpoint without binding the digest to an obvious chain, bridge,
epoch, round, or domain separator token.

This is a narrow Rust wave1 sibling of the bridge and signature domain
detectors already present in this package.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


_FN_NAME_RE = re.compile(
    r"(?i)("
    r"validator[_-]?set"
    r"|checkpoint"
    r"|set[_-]?hash"
    r"|digest"
    r"|verify"
    r")"
)

_VALIDATOR_SET_CONTEXT_RE = re.compile(
    r"(?i)\b("
    r"validator[_-]?set"
    r"|validators?"
    r"|checkpoint"
    r"|committee"
    r"|signatures?"
    r")\b"
)

_HASH_BUILD_RE = re.compile(
    r"(?i)("
    r"keccak256\s*\("
    r"|sha256\s*\("
    r"|blake2(?:b|s)?\s*\("
    r"|\.finalize\s*\("
    r"|hash\s*\("
    r"|digest\s*\("
    r")"
)

_DOMAIN_BINDING_RE = re.compile(
    r"(?i)\b("
    r"chain_id"
    r"|chainid"
    r"|network_id"
    r"|bridge_id"
    r"|domain_separator"
    r"|domain"
    r"|epoch"
    r"|round"
    r"|height"
    r"|lane_id"
    r"|client_id"
    r"|source_chain"
    r"|source_domain"
    r"|verifying_contract"
    r"|set_id"
    r"|fork_id"
    r")\b"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        if not _VALIDATOR_SET_CONTEXT_RE.search(body_nc):
            continue
        if not _HASH_BUILD_RE.search(body_nc):
            continue
        if _DOMAIN_BINDING_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` hashes or verifies validator-set checkpoint "
                    f"material without visible chain / bridge / epoch / round "
                    f"domain binding. A validator-set digest reused across "
                    f"deployments can be replayed in the wrong context."
                ),
            }
        )

    return hits
