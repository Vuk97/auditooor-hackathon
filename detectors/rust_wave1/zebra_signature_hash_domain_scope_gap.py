"""
zebra_signature_hash_domain_scope_gap.py

Flags consensus-facing Rust digest helpers that compute or verify a
transaction signature hash or tx hash without any visible domain binding
to network upgrade, consensus branch id, or transaction version split.

Zebra-fit rationale:
  - Zebra's safe path threads `NetworkUpgrade` into `SigHasher::new` and
    `to_librustzcash(nu)`.
  - Pre-V5 and V5+ transactions use different digest handling, so safe
    code typically references `version()` and/or `sighash_v4_raw`.
  - A regression that hashes transaction fields on a consensus path
    without those binders risks cross-upgrade or cross-version digest
    scope confusion.

Class: signature-hash-domain-scope-gap (rust_only).
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
    source_nocomment,
    text_of,
)


_FN_NAME_RE = re.compile(
    r"(?i)(sighash|txid|digest|hash|verify|is_valid|to_librustzcash)"
)

_DIGEST_CALL_RE = re.compile(
    r"\bsighash_v4_raw\s*\(|"
    r"(?<!::)\bsighash\s*\(|"
    r"\.txid\s*\(|"
    r"\bdigest\s*\(|"
    r"Message::from_digest\s*\(|"
    r"verify_callback\s*\("
)

_CONSENSUS_CONTEXT_RE = re.compile(
    r"(?i)(NetworkUpgrade|branch_id|consensus|transaction|sighash|txid|verify_callback)"
)

_SAFE_DOMAIN_RE = re.compile(
    r"(?i)("
    r"NetworkUpgrade|network_upgrade|branch_id|BranchId|"
    r"to_librustzcash\s*\(|"
    r"version\s*\(\)|version_group_id|"
    r"sighash_v4_raw\s*\(|"
    r"raw_bits\s*\(|"
    r"InvalidConsensusBranchId"
    r")"
)

_SAFE_PREBOUND_WRAPPER_RE = re.compile(
    r"sighash(?:_v4_raw)?\s*\(\s*&self\.precomputed_tx_data\s*,"
)

_SAFE_VERSION_SPLIT_RE = re.compile(
    r"version\s*\(\)\s*[<>!=]=?\s*5[\s\S]{0,500}"
    r"(sighash_v4_raw|(?<!::)\bsighash\s*\()|"
    r"(sighash_v4_raw|(?<!::)\bsighash\s*\()[\s\S]{0,500}"
    r"version\s*\(\)\s*[<>!=]=?\s*5"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src_nc = source_nocomment(source)

    if not _DIGEST_CALL_RE.search(src_nc):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        fn_text = text_of(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _DIGEST_CALL_RE.search(body_nc):
            continue
        if not _CONSENSUS_CONTEXT_RE.search(body_nc):
            continue

        if _SAFE_DOMAIN_RE.search(fn_text):
            continue
        if _SAFE_PREBOUND_WRAPPER_RE.search(body_nc):
            continue
        if _SAFE_VERSION_SPLIT_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` computes or verifies a transaction digest "
                    f"on a consensus-facing path without any visible network "
                    f"upgrade / branch-id / version-domain binding. In Zebra-"
                    f"class code this is a regression smell: safe paths usually "
                    f"thread `NetworkUpgrade`, call `to_librustzcash(nu)`, or "
                    f"split pre-V5 `sighash_v4_raw` from V5 typed sighash logic."
                ),
            }
        )

    return hits
