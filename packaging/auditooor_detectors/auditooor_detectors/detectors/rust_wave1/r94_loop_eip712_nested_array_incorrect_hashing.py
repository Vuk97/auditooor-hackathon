"""
r94_loop_eip712_nested_array_incorrect_hashing.py

Flags EIP-712 typed-data hashing fns that concatenate a nested
dynamic array (`uint256[2][]` / `ids_and_amounts`) directly via
`abi.encodePacked` or flat byte concatenation instead of
recursively hashing each inner element and concatenating the hashes.

Source: Solodit #61281 (Spearbit Uniswap: The Compact).
Class: eip712-nested-array-incorrect-hashing (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(fr"(?i)(hash_compact|hash_{IDENT}_claim|hash_typed_data|hash_eip712|hash_ids_amounts)")
_PACKED_CONCAT_RE = re.compile(
    fr"abi\.encodePacked\s*\(\s*{IDENT}(ids_and_amounts|ids_amounts|items_array|nested)|"
    fr"bytes::encode_packed\s*\(\s*{IDENT}nested|"
    fr"for\s+\w+\s+in\s+{IDENT}(nested|ids_and_amounts|ids_amounts|items_array|tuples|rows)[^{{]*\{{[\s\S]{{0,200}}?(result\.extend|\.extend\s*\(|concat|push_bytes)"
)
_RECURSIVE_HASH_RE = re.compile(
    r"keccak256\s*\(\s*abi\.encode\s*\([^)]*keccak256|"
    r"inner_hash|per_element_hash|element_type_hash|recursive_hash|"
    r"ids_amount_type_hash\s*=\s*keccak256"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _PACKED_CONCAT_RE.search(body_nc):
            continue
        if _RECURSIVE_HASH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` hashes a nested array via flat concat "
                f"(encodePacked / byte concat) instead of per-element "
                f"recursive hashing — EIP-712 typehash mismatches "
                f"wallet, signatures don't verify (eip712-nested-"
                f"array-incorrect-hashing). See Solodit #61281 "
                f"(Uniswap Compact)."
            ),
        })
    return hits
