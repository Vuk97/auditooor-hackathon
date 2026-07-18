"""
r94_loop_cpmm_pool_n_token_unsupported_broken.py

Flags create_pool / initialize_pool fns that accept `PoolType::ConstantProduct`
but don't restrict asset_count to exactly 2 — n>2 CPMM math is
undefined.

Source: Solodit #54977 (C4 MANTRA pool-manager).
Class: cpmm-pool-n-token-unsupported-broken (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(create_pool|initialize_pool|new_pool|register_pool|add_pool)")
_CPMM_MARKER_RE = re.compile(
    r"(PoolType::ConstantProduct|ConstantProduct|CPMM|pool_type\s*==\s*\"constant_product\")"
)
_TWO_TOKEN_GATE_RE = re.compile(
    fr"(asset_count\s*==\s*2|assets\.len\s*\(\s*\)\s*==\s*2|"
    fr"require\s*\(\s*{IDENT}assets\.length\s*==\s*2|"
    fr"require\s*\(\s*{IDENT}tokens\.length\s*==\s*2)"
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
        if not _CPMM_MARKER_RE.search(body_nc):
            continue
        if _TWO_TOKEN_GATE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` creates a ConstantProduct pool "
                f"without requiring exactly 2 tokens — CPMM invariant "
                f"only holds for 2-token pairs (cpmm-pool-n-token-"
                f"unsupported-broken). See Solodit #54977 (MANTRA)."
            ),
        })
    return hits
