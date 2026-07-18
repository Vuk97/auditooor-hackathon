"""
r94_loop_cancel_path_state_drift.py

Flags fns with a `cancelled_*` / `cancelled_partial` boolean that take
an early return AFTER setting the flag without first updating the
dependent state (stakes, sorted position, pending rewards).

Source: Solodit #46887 (OtterSec Fluid Protocol Fuel).
Class: cancel-path-state-drift (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(redeem|liquidate|cancel|process_claim|process_redemption)")

_CANCEL_SET_RE = re.compile(
    r"cancelled_\w*\s*=\s*true|cancelled\s*=\s*true|cancel_flag\s*=\s*true"
)

_EARLY_RETURN_RE = re.compile(
    r"return\s*;?\s*\}|return\s+\w+\s*;"
)

_STATE_UPDATE_RE = re.compile(
    r"update_stakes|reinsert_into_sorted|apply_pending_rewards|"
    r"checkpoint_user|update_snapshots|write_state"
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

        cancel_m = _CANCEL_SET_RE.search(body_nc)
        if cancel_m is None:
            continue
        tail = body_nc[cancel_m.end():]
        early_m = _EARLY_RETURN_RE.search(tail)
        if early_m is None:
            continue
        before_return = tail[:early_m.start()]
        if _STATE_UPDATE_RE.search(before_return):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` sets a `cancelled_*` flag and returns "
                f"early without updating dependent state (stakes / "
                f"sorted-list position / pending rewards). State drift. "
                f"See Solodit #46887 (Fluid Fuel)."
            ),
        })
    return hits
