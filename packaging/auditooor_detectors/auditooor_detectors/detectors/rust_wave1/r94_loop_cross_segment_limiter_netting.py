"""
r94_loop_cross_segment_limiter_netting.py

Flags pub fns that enforce a PER-SEGMENT daily/period cap without a
parallel global/total-across-segments cap. Attackers zig-zag between
segments to bypass the global cap.

Source: Solodit #65262 (Sherlock CurrentSUI).
Class: cross-segment-limiter-netting (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(borrow|withdraw|deposit|claim|consume)")

_PER_SEGMENT_RE = re.compile(
    r"(segments?|buckets?|tiers?|groups?|strata)\s*\[[^\]]+\]\.\w*(used|limit|cap)|"
    r"per_segment_cap|per_bucket_cap|per_tier_cap|segment_limit\s*\[|"
    r"daily_cap\s*\[[^\]]+\]|bucket_cap\s*\["
)

_GLOBAL_CHECK_RE = re.compile(
    r"total_\w*(used|limit|cap|cross)|global_\w*(used|cap|limit)|"
    fr"sum_{IDENT}across_segments|aggregate_{IDENT}cap|netted_{IDENT}cap|"
    r"\.sum\s*\(\s*\)\s*[<>!=]"
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
        if not _PER_SEGMENT_RE.search(body_nc):
            continue
        if _GLOBAL_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` enforces a per-segment daily/period cap "
                f"but no cross-segment global/netted cap. Attacker zig-"
                f"zags between segments to bypass the global limit. "
                f"See Solodit #65262 (CurrentSUI)."
            ),
        })
    return hits
