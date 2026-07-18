"""
r94_loop_htlc_zero_hashlock_accepted.py

Flags HTLC add_lock / commit / lock fns that persist a `hashlock` /
`hash_lock` parameter without asserting it's non-zero.

Source: Solodit #56667-family (Hexens Train Protocol).
Class: htlc-zero-hashlock-accepted (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(add_?lock|commit|lock|create_htlc|initiate_htlc)")

_HASHLOCK_PARAM_RE = re.compile(r"\bhashlock\b|\bhash_lock\b|\bsecret_hash\b|\bhashLock\b")

_NONZERO_CHECK_RE = re.compile(
    r"hashlock\s*!=\s*(\[\s*0|BytesN::from|Bytes::zero|0x0|\[0;\s*32\])|"
    r"hash_lock\s*!=\s*(\[\s*0|BytesN::from|Bytes::zero|0x0|\[0;\s*32\])|"
    r"require!?\s*\([^)]*hashlock\s*!=|"
    r"assert!?\s*\([^)]*hashlock\s*!=|"
    r"require!?\s*\([^)]*hash_lock\s*!=|"
    r"if\s+hashlock\s*==\s*\[\s*0"
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
        fn_text = text_of(fn, source)
        if not _HASHLOCK_PARAM_RE.search(fn_text):
            continue
        body_nc = body_text_nocomment(body, source)
        if _NONZERO_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` accepts a `hashlock`/`hash_lock` arg "
                f"without asserting it's non-zero. A zero hashlock is "
                f"trivially unlockable (anyone provides `sha256([])` / "
                f"all-zero preimage). See Hexens Train Protocol "
                f"LYSWP2-8."
            ),
        })
    return hits
