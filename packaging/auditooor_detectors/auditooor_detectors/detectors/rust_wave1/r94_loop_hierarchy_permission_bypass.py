"""
r94_loop_hierarchy_permission_bypass.py

Flags model/resource-level mutation fns that check ONLY a local owner
(e.g. `require(caller == model.owner)`) without also consulting a
parent-level owner (namespace_owner / world_owner).

Source: Solodit #43623 (OpenZeppelin Dojo).
Class: hierarchy-permission-bypass (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment, IDENT, CALL,
)

_FN_NAME_RE = re.compile(r"(?i)(set|update|modify|edit|configure|transfer_ownership)_?\w*(model|resource|module|field)")
_LOCAL_OWNER_RE = re.compile(
    fr"(caller|msg\.sender|sender)\s*==\s*{IDENT}\.owner|"
    fr"require!?\s*\([^)]*(caller|sender|msg\.sender)\s*==\s*{IDENT}\.owner"
)
_HIERARCHICAL_RE = re.compile(
    fr"namespace_owner|world_owner|parent_owner|world::is_owner|"
    fr"check_hierarchical|hierarchy_check|assert_world_access|"
    fr"owner_of_namespace|world\.is_{IDENT}owner"
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
        if not _LOCAL_OWNER_RE.search(body_nc):
            continue
        if _HIERARCHICAL_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` checks only the local owner without "
                f"consulting the hierarchical namespace/world owner. "
                f"Higher-level owner is bypassed. See Solodit #43623 (Dojo)."
            ),
        })
    return hits
