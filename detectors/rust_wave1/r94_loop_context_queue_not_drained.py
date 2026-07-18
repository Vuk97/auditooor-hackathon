"""
r94_loop_context_queue_not_drained.py

Flags pub fns that append to a named queue/slice/vec but no sibling fn
in the same module drains/removes from that queue.

Source: Solodit #55306 (Initia minievm ExecuteRequests).
Class: context-queue-not-drained (both).
"""

from __future__ import annotations
import re
from _util import (
    source_nocomment, functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_APPEND_RE = re.compile(
    r"(\w+)\s*=\s*append\s*\(\s*\1\s*,|"       # Go-style append(x, ...)
    r"(\w+)\.push\s*\(|\.push_back\s*\(|"
    r"vec\.push\s*\("
)

_DRAIN_RE = re.compile(
    r"\.drain\s*\(|\.clear\s*\(|\.truncate\s*\(|\.remove\s*\(|"
    r"\.pop\s*\(|\.pop_front\s*\(|\.pop_back\s*\(|"
    r"\w+\s*=\s*append\s*\(\s*\w+\[\s*:0\s*\]|"  # Go reset slice
    fr"reset_{IDENT}queue|drain_\w*|flush_\w*"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    src_nc = source_nocomment(source)

    # Does the source have a drain / clear / pop anywhere?
    if _DRAIN_RE.search(src_nc):
        return hits

    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        m = _APPEND_RE.search(body_nc)
        if m is None:
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` appends to a queue/vec/slice but no "
                f"sibling fn in this module drains (drain/pop/clear/"
                f"truncate/reset) from it. Accumulated entries can replay "
                f"across invocations. See Solodit #55306 (Initia)."
            ),
        })
    return hits
