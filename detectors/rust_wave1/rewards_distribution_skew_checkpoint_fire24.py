"""
rewards_distribution_skew_checkpoint_fire24.py

Fire24 Rust lift for rewards-distribution-skew branches where a claim or
settlement arm advances only user-side reward state. The detector looks for
branches that write reward_debt, claimed, checkpoint, multiplier, boost, or
weight state while the sibling branch performs the global accumulator, total
supply, or total reward debt update.

Detector hits are candidate evidence only. R40 and R80 still require a real
protocol path, mutation-verified non-vacuous evidence, and a clean negative
control before any finding can rely on a hit.

Class: rewards-distribution-skew.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    source_nocomment,
)


_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(claim|harvest|settle|reward|emission|incentive|pending|"
    r"claimable|earned|payout|accumulator|reward_?debt|"
    r"reward_?per_?(?:share|token|weight)|acc_?reward|global_?index|"
    r"checkpoint|claimed|multiplier|boost|total_?(?:supply|stake|shares|weight))"
)

_FN_NAME_RE = re.compile(
    r"(?i)(claim|harvest|settle|collect|release|distribute|checkpoint|"
    r"update_?user|sync_?user|handle_?balance_?update|refresh_?multiplier|"
    r"update_?stake_?weight|stake|unstake|deposit|withdraw)"
)

_USER_CONTAINER_RE = (
    r"(?:self\.)?(?:users?|accounts?|positions?|stakes?|stakers|"
    r"user_?info|reward_?info|checkpoints?)\s*\[[^\]]+\]\s*\.\s*"
)
_USER_FIELD_RE = (
    r"(?:reward_?debt|reward_?index|reward_?checkpoint|"
    r"reward_?per_?(?:token|share|weight)_?paid|paid_?index|"
    r"user_?reward_?index|checkpoint|amount_?claimed|claimed|"
    r"multiplier|boost|boost_?factor|weight|stake_?weight)"
)

_USER_STATE_UPDATE_RE = re.compile(
    rf"(?is)(?:{_USER_CONTAINER_RE}{_USER_FIELD_RE}\s*(?:=|\+=|-=)|"
    rf"{_USER_FIELD_RE}\s*\[[^\]]+\]\s*(?:=|\+=|-=)|"
    rf"(?:set|save|store|write|record|mark|checkpoint)_"
    rf"(?:user_?)?(?:reward_?debt|reward_?index|reward_?checkpoint|"
    rf"reward_?paid|claim(?:ed)?|checkpoint|multiplier|boost|weight)\s*\()"
)

_GLOBAL_FIELD_RE = (
    r"(?:acc_?reward_?per_?(?:share|token|weight)|reward_?per_?(?:share|token|weight)|"
    r"reward_?per_?token_?stored|global_?reward_?index|reward_?index|"
    r"reward_?accumulator|total_?(?:supply|stake|shares|weight|reward_?debt|"
    r"claimed|claimable|rewards?)|pool_?reward_?debt|emission_?index)"
)
_GLOBAL_RECEIVER_RE = (
    r"(?:self|state|pool|strategy|staking|distributor)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*|\s*\[[^\]]+\]){0,4}"
)

_GLOBAL_UPDATE_RE = re.compile(
    rf"(?is)(?:"
    rf"(?:\b|\.)"
    rf"(?:update|sync|settle|checkpoint|accrue|refresh)_"
    rf"(?:global_?)?(?:reward|rewards|reward_?index|accumulator|"
    rf"reward_?accumulator|reward_?per_?(?:share|token|weight)|"
    rf"pool|supply|total|emission)\s*\(|"
    rf"{_GLOBAL_RECEIVER_RE}\s*\.\s*{_GLOBAL_FIELD_RE}\s*(?:=|\+=|-=)|"
    rf"\b{_GLOBAL_FIELD_RE}\b\s*(?:=|\+=|-=)"
    rf")"
)

_REWARD_VALUE_EFFECT_RE = re.compile(
    r"(?is)(?:transfer_?reward|pay_?reward|credit_?reward|release_?reward|"
    r"distribute_?reward|mint_?reward|send_?reward|claim_?reward|"
    r"pending_?reward|claimable_?reward|earned_?reward|owed|payout|"
    r"\bamount\b|\breward\b)"
)


class BranchPair(NamedTuple):
    if_condition: str
    if_body: str
    if_start: int
    else_body: str
    else_start: int
    end: int


def _find_matching_delimiter(source: str, open_pos: int) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != "{":
        return -1
    depth = 1
    i = open_pos + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _extract_block(source: str, open_brace: int) -> tuple[str | None, int]:
    close = _find_matching_delimiter(source, open_brace)
    if close < 0:
        return None, open_brace
    return source[open_brace + 1:close], close + 1


def _skip_ws(source: str, pos: int) -> int:
    while pos < len(source) and source[pos].isspace():
        pos += 1
    return pos


def _branch_pairs(body: str) -> list[BranchPair]:
    pairs: list[BranchPair] = []
    pos = 0
    while True:
        match = re.search(r"\bif\b", body[pos:])
        if match is None:
            break
        if_start = pos + match.start()
        condition_start = pos + match.end()
        if_block_start = body.find("{", condition_start)
        if if_block_start < 0:
            break

        if_condition = body[condition_start:if_block_start].strip()
        if_body, after_if = _extract_block(body, if_block_start)
        if if_body is None:
            pos = if_start + 2
            continue

        else_pos = _skip_ws(body, after_if)
        if not body.startswith("else", else_pos):
            pos = after_if
            continue

        else_block_start = _skip_ws(body, else_pos + len("else"))
        if else_block_start >= len(body) or body[else_block_start] != "{":
            pos = after_if
            continue

        else_body, after_else = _extract_block(body, else_block_start)
        if else_body is None:
            pos = after_if
            continue

        pairs.append(
            BranchPair(
                if_condition=if_condition,
                if_body=if_body,
                if_start=if_start,
                else_body=else_body,
                else_start=else_block_start,
                end=after_else,
            )
        )
        pos = after_if
    return pairs


def _branch_has_reward_work(branch: str, sibling: str, name: str) -> bool:
    haystack = f"{name}\n{branch}\n{sibling}"
    return bool(_REWARD_VALUE_EFFECT_RE.search(haystack))


def _unsafe_user_only_branch(name: str, branch: str, sibling: str, pre: str) -> bool:
    if _USER_STATE_UPDATE_RE.search(branch) is None:
        return False
    if not _branch_has_reward_work(branch, sibling, name):
        return False
    if _GLOBAL_UPDATE_RE.search(pre):
        return False
    if _GLOBAL_UPDATE_RE.search(branch):
        return False
    return _GLOBAL_UPDATE_RE.search(sibling) is not None


def _shape_for(name: str, body: str) -> str | None:
    for pair in _branch_pairs(body):
        pre = body[: pair.if_start]
        if _unsafe_user_only_branch(name, pair.if_body, pair.else_body, pre):
            return "if-arm-user-state-without-global"
        if _unsafe_user_only_branch(name, pair.else_body, pair.if_body, pre):
            return "else-arm-user-state-without-global"
    return None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    source_text = source_nocomment(source)
    if not _REWARD_CONTEXT_RE.search(source_text):
        return hits

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
        shape = _shape_for(name, body_nc)
        if shape is None:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` has a reward claim or settlement branch "
                f"that advances user reward debt, checkpoint, claimed, "
                f"multiplier, boost, or weight state without the sibling "
                f"global accumulator, total supply, or total reward debt "
                f"update ({shape}; rewards-distribution-skew, Fire24 "
                f"checkpoint branch lift)."
            ),
        })
    return hits
