"""
two_step_admin_missing.py

Flags single-step admin transfer setters when the same *crate/file* exposes
neither a propose_admin / accept_admin nor a pending_admin key.

Heuristic:
  - Gather all fn names in this file.
  - Candidate "setter" fns: names like `set_admin`, `transfer_admin`,
    `update_admin`, `set_owner`, `transfer_ownership`.
  - If any SIBLING function name contains `propose` or `pending` or `accept`
    (case-insensitive), assume two-step pattern exists → skip this file.
  - Also: if the function body itself stages a pending admin (writes a
    DataKey containing `Pending` / `PENDING`), skip.
  - Otherwise: flag the setter.

Halborn §7.34, §7.45.
"""

from __future__ import annotations

from _util import (
    function_items, fn_body, fn_name, is_pub, text_of, walk_no_nested_fn,
    line_col, snippet_of,
)


_SETTER_NAMES = (
    "set_admin", "transfer_admin", "update_admin", "change_admin",
    "set_owner", "set_ownership", "transfer_ownership", "update_owner",
)

_TWO_STEP_MARKERS = ("propose", "pending", "accept", "commit_admin",
                     "claim_admin", "claim_ownership")


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node

    # Gather sibling fn names to see if two-step pattern is present
    sibling_names = set()
    for fn in function_items(root):
        sibling_names.add(fn_name(fn, source).lower())

    # If ANY sibling contains a two-step marker, skip the whole file
    if any(any(m in n for m in _TWO_STEP_MARKERS) for n in sibling_names):
        return hits

    # Also check if file source mentions a PendingAdmin-like DataKey variant
    src_text = source.decode("utf-8", errors="replace").lower()
    if "pendingadmin" in src_text or "pending_admin" in src_text:
        return hits

    for fn in function_items(root):
        name = fn_name(fn, source)
        if name.lower() not in _SETTER_NAMES:
            continue
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source).lower()
        if any(m in body_text for m in _TWO_STEP_MARKERS):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "med",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source, max_len=120),
            "message": (f"pub fn `{name}` is a single-step admin/owner "
                        f"setter with no sibling propose/accept pattern "
                        f"(Halborn §7.34/§7.45)."),
        })
    return hits
