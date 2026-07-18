"""
r94_loop_field_modulus_timestamp_overflow.py

Flags ZK-VM / prime-field fns where `timestamp`, `clock`, or a counter
is ADVANCED without a bound check against the field modulus (BabyBear,
Goldilocks, Pallas, etc.).

Source: Solodit #53416 (Cantina OpenVM).
Class: field-modulus-timestamp-overflow (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment, IDENT, CALL,
)

_CTX_RE = re.compile(r"BabyBear|Goldilocks|Pallas|Mersenne|field::|F::|Fp::")
_MUT_COUNTER_RE = re.compile(
    r"timestamp\s*(\+=|=\s*timestamp\s*\+)|"
    r"clock\s*(\+=|=\s*clock\s*\+)|"
    r"counter\s*(\+=|=\s*counter\s*\+)|"
    r"step_counter\s*(\+=|=)"
)
_MODULUS_CHECK_RE = re.compile(
    fr"MODULUS|FIELD_ORDER|field_modulus|assert!?\s*\(\s*{IDENT}timestamp\s*<\s*{IDENT}MOD|"
    fr"require!?\s*\(\s*{IDENT}timestamp\s*<\s*{IDENT}MOD|wrap_into_field|to_canonical"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        # Combine module context with the body (ZK field constants usually at top)
        src_head = source[:8000].decode("utf8", errors="replace")
        if not _CTX_RE.search(src_head + body_nc):
            continue
        if not _MUT_COUNTER_RE.search(body_nc):
            continue
        if _MODULUS_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` advances a timestamp/clock/counter in a "
                f"ZK-VM / prime-field context without an explicit bound "
                f"check against the field modulus. Counter wraps past "
                f"MODULUS — invalid program paths executable and verifiable. "
                f"See Solodit #53416 (OpenVM)."
            ),
        })
    return hits
