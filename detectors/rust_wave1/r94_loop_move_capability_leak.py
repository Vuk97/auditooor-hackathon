"""
r94_loop_move_capability_leak.py

Flags Move/Sui pub fns that RETURN or ACCEPT-and-forward a capability-
typed value (ends in `Cap`, e.g. `TreasuryCap`, `AdminCap`, `MinterCap`,
`UpgradeCap`) without a signer restriction or a consume-at-site pattern.
Capabilities confer privileged power — passing them through public
functions leaks that power to the caller.

Source: pattern across OtterSec / Zellic Move/Sui reviews.
Class: move-capability-leak (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_CAP_TY_RE = re.compile(r"\b[A-Z][A-Za-z]*Cap\b|\bTreasuryCap<|\bAdminCap\b|\bUpgradeCap\b|\bMinterCap\b|\bMintCap\b")
_CONSUME_RE = re.compile(
    r"transfer::(transfer|public_transfer)|"
    fr"move_to\s*\(|object::delete|destroy_{IDENT}cap|burn_cap"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        # Check full function signature (params + return type) for Cap types
        fn_text = text_of(fn, source)
        # Only the signature part (up to the first { )
        sig_end = fn_text.find("{")
        if sig_end == -1:
            continue
        sig_part = fn_text[:sig_end]
        if not _CAP_TY_RE.search(sig_part):
            continue

        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if _CONSUME_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_part[:200].strip(),
            "message": (
                f"pub fn `{name}` accepts or returns a capability-typed "
                f"value (name ends in `Cap`) without a consume-at-site "
                f"pattern (transfer / move_to / object::delete). "
                f"Capability leaks to caller → privileged power escalation."
            ),
        })
    return hits
