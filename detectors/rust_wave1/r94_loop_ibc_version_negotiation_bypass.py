"""
r94_loop_ibc_version_negotiation_bypass.py

Flags Cosmos-SDK IBC middleware `OnChanOpenInit` / `OnChanOpenTry`
fns that return the INPUT version arg instead of the NEGOTIATED
version returned by the underlying-app invocation.

Source: Solodit #55319 (Code4rena Initia ibc-hooks).
Class: ibc-version-negotiation-bypass (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment, IDENT, CALL,
)

_FN_NAME_RE = re.compile(r"(?i)(on_?chan_?open_?init|on_?chan_?open_?try|onChanOpenInit|onChanOpenTry)")


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
        # Must have both version input and an underlying app call
        has_app_negotiate = bool(re.search(
            r"app\.(on_chan_open_init|on_chan_open_try|onChanOpenInit|onChanOpenTry)|"
            r"underlying\w*\.on_chan_open|OnChanOpenInit\s*\(\s*ctx",
            body_nc,
        ))
        if not has_app_negotiate:
            continue
        # Return the ORIGINAL version instead of the negotiated one
        returns_original = bool(re.search(
            r"return\s+version\s*,?|Ok\s*\(\s*version\s*\)|\s*version\s*\n\s*\}|"
            r"return\s+ctx\.version",
            body_nc,
        ))
        returns_negotiated = bool(re.search(
            fr"return\s+{IDENT}finalVersion|Ok\s*\(\s*{IDENT}negotiated_?version\s*\)|"
            fr"return\s+{IDENT}new_?version|return\s+{IDENT}negotiated",
            body_nc,
        ))
        if returns_original and not returns_negotiated:
            line, col = line_col(fn)
            hits.append({
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` invokes the underlying app's "
                    f"OnChanOpenInit/Try (which returns the negotiated "
                    f"version) but then returns the caller's original "
                    f"`version` arg. IBC middleware stack version drift. "
                    f"See Solodit #55319 (Initia)."
                ),
            })
    return hits
