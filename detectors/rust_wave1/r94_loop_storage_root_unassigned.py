"""
r94_loop_storage_root_unassigned.py

Flags fns with a `storage_root` / `root` return variable that is
declared / pre-initialized but never assigned from the actual merkle-
tree computation before return.

Source: Solodit #55294 (Code4rena Initia opinit-bots).
Class: storage-root-assignment-missing (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(handle_?tree|finalize_?tree|compute_?root|build_?root|storage_?root)")


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

        # Must declare a root-named variable
        decl_m = re.search(fr"(?:let\s+(?:mut\s+)?)?(storage_root|root_hash|merkle_root)\s*:\s*[^=]+=\s*{IDENT}default\s*\(\s*\)|"
                            r"let\s+(?:mut\s+)?(storage_root|root_hash|merkle_root)\s*:\s*[^=]+=\s*\[0",
                            body_nc)
        if decl_m is None:
            continue
        var_name = decl_m.group(1) or decl_m.group(2)
        # Must NOT assign it later (no `storage_root = ...` or `*storage_root = ...`)
        if re.search(rf"\b{re.escape(var_name)}\s*=\s*\w", body_nc[decl_m.end():]):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` declares `{var_name}` as a default/zero "
                f"placeholder but never assigns the actual computed root "
                f"before return. Downstream sync reads the zero value. "
                f"See Solodit #55294 (Initia opinit-bots)."
            ),
        })
    return hits
