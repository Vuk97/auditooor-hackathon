"""
r94_loop_delegation_overwrite_no_auth.py

Flags public fns that mutate another user's delegation / boost /
voting-power map but don't require_auth the caller OR check
caller == target.

Source: Solodit #57206 (Regnum Aurum BoostController).
Class: delegation-overwrite-no-auth (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(update_user_boost|update_delegation|set_delegate|delegate_to|"
    r"transfer_delegation|update_boost)"
)
_WRITES_USER_STATE_RE = re.compile(
    r"(delegations|boost_of|user_boost|voting_power)\s*\(\s*\&?(user|target|victim|account)|"
    r"\.insert\s*\(\s*\&?(user|target|account),|"
    r"self\.(delegations|boost_of|user_boost|voting_power)"
)
_AUTH_RE = re.compile(
    r"require_auth\s*\(\s*\&?(user|target|account|caller)|"
    r"caller\s*==\s*(user|target|account)|"
    r"env\.invoker\s*\(\s*\)\s*==\s*(user|target|account)|"
    r"assert[!_]?eq\s*\(\s*caller\s*,\s*(user|target|account)"
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
        if not _WRITES_USER_STATE_RE.search(body_nc):
            continue
        if _AUTH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` mutates another user's delegation/"
                f"boost/voting_power without require_auth(user) — "
                f"anyone DoS's victim by overwriting delegation "
                f"(delegation-overwrite-no-auth). See Solodit #57206 "
                f"(Regnum Aurum BoostController)."
            ),
        })
    return hits
