"""
r94_loop_namespace_hash_inconsistency.py

Flags pub fns accepting a namespace NAME and a namespace HASH as
separate params and registering without cross-validating that
hash(name) == hash.

Source: Solodit #43622 (OpenZeppelin Dojo).
Class: namespace-hash-inconsistency (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(register|update)_?(model|namespace|resource|type)")
_BOTH_PARAMS_RE = re.compile(
    r"(name|namespace)\s*:\s*\w+.*?(hash|namespace_hash|ns_hash)\s*:|"
    r"(hash|namespace_hash|ns_hash)\s*:\s*\w+.*?(name|namespace)\s*:",
    re.DOTALL,
)
_HASH_OF_NAME_CHECK_RE = re.compile(
    r"hash\s*\(\s*name\s*\)\s*==|poseidon\s*\([^)]*name[^)]*\)\s*==|"
    fr"compute_namespace_hash\s*\(\s*name|assert!?\s*\(\s*hash\s*==\s*{IDENT}hash|"
    fr"require!?\s*\(\s*{IDENT}hash\s*==\s*hash\s*\("
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
        fn_text = text_of(fn, source)
        sig_end = fn_text.find("{")
        if sig_end == -1:
            continue
        sig = fn_text[:sig_end]
        if not _BOTH_PARAMS_RE.search(sig):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if _HASH_OF_NAME_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig[:200].strip(),
            "message": (
                f"pub fn `{name}` takes both `name` and `hash` as params "
                f"but does not cross-validate `hash(name) == hash` before "
                f"use. Caller can spoof a namespace by supplying "
                f"mismatched pair. See Solodit #43622 (Dojo)."
            ),
        })
    return hits
