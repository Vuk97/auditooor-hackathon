"""
r94_loop_commitment_caller_not_collateral_owner.py

Flags loan commitment / lien validation fns that check caller OR
receiver OR signature (`||` chain) but don't bind caller == collateral
owner — anyone mints a lien against someone else's NFT.

Source: Solodit #7301 (Astaria _validateCommitment).
Class: commitment-caller-not-collateral-owner (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(validate_commitment|open_lien|commit_to_lien|commit_loan|"
    r"validate_loan|borrow_on_behalf|start_commitment)"
)
# at-least-one-of-check pattern (disjunction)
_DISJ_AUTH_RE = re.compile(
    r"caller\s*==\s*\w+\s*\|\|\s*\w+\s*==\s*\w+|"
    r"is_caller\s*\(\s*\)\s*\|\|\s*is_receiver|"
    r"\|\|\s*verify_signature\s*\(|\|\|\s*\w+\.verify\s*\("
)
_COLLATERAL_OWNER_CHECK_RE = re.compile(
    r"require_auth\s*\(\s*(collateral_owner|nft_owner|token_owner)|"
    r"assert[!_]?eq\s*\(\s*caller\s*,\s*(collateral_owner|nft_owner|token_owner)|"
    r"caller\s*==\s*(collateral_owner|nft_owner|token_owner)|"
    r"owner_of\s*\([^)]*\)\s*==\s*caller"
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
        if not _DISJ_AUTH_RE.search(body_nc):
            continue
        if _COLLATERAL_OWNER_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` authorizes via caller||receiver|| "
                f"signature disjunction but never binds caller == "
                f"collateral_owner — attacker mints a lien against "
                f"victim's NFT (commitment-caller-not-collateral-owner). "
                f"See Solodit #7301 (Astaria)."
            ),
        })
    return hits
