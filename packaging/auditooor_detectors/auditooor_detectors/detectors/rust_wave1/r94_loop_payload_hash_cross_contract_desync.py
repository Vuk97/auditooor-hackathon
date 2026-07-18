"""
r94_loop_payload_hash_cross_contract_desync.py

Flags fns that compute/verify a payload hash using a specific formula
(keccak256/sha256 of a concatenation/serialization) while a paired
sibling fn in the same module uses a different formula. Cross-contract
hash desync lets attackers forge payloads that pass one check and fail
another.

Source: Solodit #53223 (OtterSec Mayan Solana).
Class: payload-hash-cross-contract-desync (both).

Heuristic:
  1. Scan all pub fns with names matching /verify|init|post|check/ etc.
  2. Collect the keccak256/sha256 payload-derivation expressions
     (argument lists into keccak256/sha256).
  3. If ≥ 2 distinct derivation expressions exist in the same module
     and they reference the same variable/field set but in a different
     ORDER / different separator / different prefix — flag.

For a tractable heuristic: flag any contract-module that:
  - has ≥ 2 hash-derivation sites, AND
  - where at least one site uses `borsh::to_vec` / `abi.encodePacked`
    and another uses raw-concat `&[..., ..., ...]` without any
    common helper fn call (indicating the derivations diverged).
"""

from __future__ import annotations

import re

from _util import (
    source_nocomment,
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_HASH_CALL_RE = re.compile(
    r"keccak256\s*\(|sha256\s*\(|blake2b\s*\(|hash::hashv?\s*\("
)

_BORSH_RE = re.compile(r"borsh::to_vec|borsh_serialize|BorshSerialize")
_RAW_CONCAT_RE = re.compile(r"&\[[^\]]*,[^\]]*,[^\]]*\]|\bconcat!?\s*\(")
_COMMON_HELPER_RE = re.compile(r"compute_payload_hash|build_hash|derive_hash|payload_digest")


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    source_str = source.decode("utf8", errors="replace")
    # Strip comments once at module level
    import re as _re
    src_nc = _re.sub(r"//[^\n]*", "", source_str)
    src_nc = _re.sub(r"/\*.*?\*/", "", src_nc, flags=_re.DOTALL)

    hash_sites = _HASH_CALL_RE.findall(src_nc)
    if len(hash_sites) < 2:
        return hits  # not enough sites to desync
    if _COMMON_HELPER_RE.search(src_nc):
        return hits  # likely shared helper

    uses_borsh = bool(_BORSH_RE.search(src_nc))
    uses_raw = bool(_RAW_CONCAT_RE.search(src_nc))
    if not (uses_borsh and uses_raw):
        # Need BOTH derivation styles present to suspect desync
        return hits

    # Emit one hit per pub fn that does a hash call with the divergent style
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _HASH_CALL_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes a payload hash in this "
                f"contract module which contains BOTH borsh-serialize "
                f"AND raw-concat hash derivations with no shared helper. "
                f"Likely cross-contract desync — sibling fn hashes "
                f"differently. See Solodit #53223 (Mayan Solana)."
            ),
        })
    return hits
