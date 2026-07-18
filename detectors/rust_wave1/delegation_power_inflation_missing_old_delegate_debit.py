"""
delegation_power_inflation_missing_old_delegate_debit.py

Flags Rust delegation reassignment paths that add voting or delegation
power to the new delegate without subtracting or clearing the previous
delegate's power first.

Source: reference/patterns.dsl/w68-delegation-power-inflation-no-debit.yaml
Class: delegation-power-inflation (both).
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


_FN_NAME_RE = re.compile(
    r"(?i)(delegate|redelegate|set_delegate|change_delegate|"
    r"update_delegation|transfer_delegation|move_delegation|"
    r"assign_delegate|reassign_delegate)"
)

_POWER_MAP = (
    r"(?:delegation_power|delegate_power|delegated_power|"
    r"voting_power|vote_power|delegate_votes|delegated_votes|"
    r"votes_by_delegate)"
)
_DELEGATION_EDGE = (
    r"(?:delegations|delegates|delegate_of|delegated_to|"
    r"current_delegate|delegatee_of|delegation_of)"
)
_OLD_DELEGATE = (
    r"(?:old_delegate|prev_delegate|previous_delegate|prior_delegate|"
    r"current_delegate|existing_delegate|from_delegate|former_delegate|"
    r"old_validator|previous_validator|from_validator)"
)
_NEW_DELEGATE = (
    r"(?:new_delegate|new_delegatee|delegatee|to_delegate|target_delegate|"
    r"next_delegate|new_validator|to_validator)"
)
_AMOUNT = r"(?:amount|power|weight|votes|balance|stake|voting_power)"

_OLD_DELEGATE_READ_RE = re.compile(
    fr"(?is)\b{_OLD_DELEGATE}\b.{{0,220}}(?:{_DELEGATION_EDGE}|\.get\s*\(|\[)|"
    fr"(?:{_DELEGATION_EDGE}).{{0,220}}\b{_OLD_DELEGATE}\b"
)
_EDGE_REASSIGN_RE = re.compile(
    fr"(?is)(?:{_DELEGATION_EDGE}).{{0,180}}"
    fr"(?:insert\s*\(|set\s*\(|\[).{{0,180}}\b{_NEW_DELEGATE}\b"
)
_NEW_POWER_CREDIT_RE = re.compile(
    fr"(?is)(?:{_POWER_MAP}).{{0,260}}"
    fr"(?:entry\s*\(|insert\s*\(|set\s*\(|\[).{{0,260}}"
    fr"\b{_NEW_DELEGATE}\b.{{0,260}}"
    fr"(?:\+=|\+\s*{_AMOUNT}\b|saturating_add\s*\(|checked_add\s*\(|"
    fr"or_insert\s*\(\s*{_AMOUNT}\b)"
)
_OLD_POWER_DEBIT_RE = re.compile(
    fr"(?is)(?:{_POWER_MAP}).{{0,260}}\b{_OLD_DELEGATE}\b.{{0,260}}"
    fr"(?:-=|-\s*{_AMOUNT}\b|saturating_sub\s*\(|checked_sub\s*\(|"
    fr"remove\s*\(|take\s*\(|clear\s*\()|"
    fr"(?:remove|clear|take).{{0,180}}\b{_OLD_DELEGATE}\b|"
    fr"\b(?:move_delegate_votes|move_delegation_power|"
    fr"debit_old_delegate|subtract_old_delegate|clear_old_delegate|"
    fr"remove_from_old_delegate)\s*\("
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        if not _OLD_DELEGATE_READ_RE.search(body_nc):
            continue
        if not _EDGE_REASSIGN_RE.search(body_nc):
            continue
        if not _NEW_POWER_CREDIT_RE.search(body_nc):
            continue
        if _OLD_POWER_DEBIT_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reassigns a delegator and credits the "
                f"new delegate's voting power without debiting or clearing "
                f"the old delegate first. Repeated reassignment can inflate "
                f"delegation power (delegation-power-inflation)."
            ),
        })
    return hits
