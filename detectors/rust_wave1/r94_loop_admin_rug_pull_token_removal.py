"""
r94_loop_admin_rug_pull_token_removal.py

Flags admin-gated fns that REMOVE tokens from a shared basket /
vault / portfolio without a governance delay / veto / checkpoint.

Source: Solodit #55600 (TOB Reserve Solana DTFs).
Class: admin-rug-pull-token-removal (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(remove_?token|remove_?asset|delist_?asset|retire_?token|drop_?basket_?token)")
_ADMIN_GATE_RE = re.compile(
    r"Role::Owner|is_owner|only_owner|require!?\s*\([^)]*owner|"
    r"require!?\s*\([^)]*admin|is_admin|has_role\(ADMIN\)"
)
_DELAY_OR_VETO_RE = re.compile(
    r"timelock|governance_delay|veto_window|challenge_period|"
    r"queue_proposal|schedule\s*\(|propose\s*\(|"
    r"vote_threshold|multisig_required|two_step"
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
        if not _ADMIN_GATE_RE.search(body_nc):
            continue
        if _DELAY_OR_VETO_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` lets admin/owner remove tokens/assets "
                f"from a shared basket with no timelock/governance-delay/"
                f"veto/multisig. Admin rug-pull surface. See Solodit "
                f"#55600 (Reserve Solana DTFs)."
            ),
        })
    return hits
