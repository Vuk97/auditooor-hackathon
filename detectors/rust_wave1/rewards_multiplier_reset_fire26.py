"""
rewards_multiplier_reset_fire26.py

Fire26 same-class Rust lift for rewards-distribution-skew misses where
reward multiplier, reward index, or staking balance state is reset or
overwritten from a public user-controlled flow instead of preserving the
previous accounting state.

Source-backed Rust seed misses:
- r94-loop-reward-multiplier-reset-by-griefer-positive
- r94-loop-staking-balance-overwrite-not-add-positive

Class: rewards-distribution-skew.
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
    source_nocomment,
    text_of,
)


_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(reward|rewards|multiplier|boost|stake|staked|staking|"
    r"weight|reward_?index|reward_?debt|balance)"
)

_USER_ARG_RE = re.compile(
    r"(?i)\b(user|account|staker|delegator|target|owner|who|beneficiary)\s*:"
)

_AMOUNT_ARG_RE = re.compile(
    r"(?i)\b(amount|delta|shares|new_?balance|new_?weight|stake_?amount)\s*:"
)

_RESET_FN_RE = re.compile(
    r"(?i)(handle_?balance_?update|update_?user_?weight|"
    r"refresh_?multiplier|sync_?user|recompute_?boost|"
    r"update_?stake_?weight|update_?position|claim_?rewards?_?for)"
)

_STAKE_FN_RE = re.compile(
    r"(?i)^(stake|deposit_?stake|add_?stake|enter_?stake|"
    r"update_?stake_?balance|set_?stake)$"
)

_RESET_WRITE_RE = re.compile(
    r"(?is)("
    r"(?:multiplier|boost|stake_?weight|reward_?(?:index|debt))"
    r"[A-Za-z0-9_\.\[\]\s]*"
    r"(?:=\s*(?:0|1)\b|"
    r"\.\s*(?:insert|set)\s*\([^,]+,\s*(?:0|1)\s*\))"
    r"|"
    r"(?:reset_?multiplier|set_?multiplier|set_?boost|"
    r"set_?reward_?index)\s*\([^)]*,\s*(?:0|1)\s*\)"
    r")"
)

_CALLER_GATED_RE = re.compile(
    r"(?is)("
    r"require_?auth\s*\(\s*(?:&\s*)?(?:user|account|staker|target|owner|who)"
    r"|(?:user|account|staker|target|owner|who)\s*\.\s*require_?auth\s*\("
    r"|require_?user\s*\(\s*(?:user|account|staker|target|owner|who)"
    r"|only_?user\s*\(\s*(?:user|account|staker|target|owner|who)"
    r"|assert_?user\s*\(\s*(?:user|account|staker|target|owner|who)"
    r"|assert_?eq!?\s*\(\s*caller\s*,\s*(?:user|account|staker|target|owner|who)"
    r"|caller\s*==\s*(?:user|account|staker|target|owner|who)"
    r"|ensure_signed\s*\("
    r")"
)

_OVERWRITE_ASSIGN_RE = re.compile(
    r"(?is)("
    r"(?:self|state|pool)\s*\.\s*(?:users|accounts|positions)"
    r"\s*\[[^\]]+\]\s*\.\s*"
    r"(?:staked|stake|stake_balance|staking_balance|shares|balance|weight)"
    r"\s*=\s*"
    r"(?:amount|delta|shares|new_?balance|new_?weight|stake_?amount)\b"
    r"|"
    r"(?:self\.)?"
    r"(?:staked_?balance|stake_?balance|staking_?balance|user_?stakes|"
    r"stake_?by_?user|stakes|positions)"
    r"\s*\[[^\]]*(?:user|account|staker|owner|caller|who)[^\]]*\]"
    r"\s*=\s*"
    r"(?:amount|delta|shares|new_?balance|new_?weight|stake_?amount)\b"
    r"|"
    r"(?:self|state|pool)\s*\.\s*"
    r"(?:staked_?balance|stake_?balance|staking_?balance|staked|stake|shares)"
    r"\s*=\s*"
    r"(?:amount|delta|shares|new_?balance|new_?weight|stake_?amount)\b"
    r")"
)

_OVERWRITE_INSERT_RE = re.compile(
    r"(?is)"
    r"(?:self\.)?"
    r"(?:staked_?balance|stake_?balance|staking_?balance|user_?stakes|"
    r"stake_?by_?user|stakes|positions)"
    r"\s*\.\s*(?:insert|set)\s*\(\s*"
    r"(?:&\s*)?(?:user|account|staker|owner|caller|who)\s*,\s*"
    r"(?:amount|delta|shares|new_?balance|new_?weight|stake_?amount)\s*\)"
)

_ACCUMULATE_PREVIOUS_RE = re.compile(
    r"(?is)("
    r"\+=|"
    r"(?:checked|saturating|wrapping)_add\s*\(|"
    r"\b(?:previous|prev|existing|old|current)_?"
    r"(?:balance|stake|shares|weight|amount)?\b[^;\n]*\+|"
    r"\+\s*(?:amount|delta|shares|new_?balance|new_?weight|stake_?amount)\b|"
    r"(?:amount|delta|shares|new_?balance|new_?weight|stake_?amount)\s*\+|"
    r"\.\s*entry\s*\([^)]*\)\s*\.\s*and_modify\s*\("
    r")"
)


def _signature(fn, source: bytes) -> str:
    text = text_of(fn, source)
    return text.split("{", 1)[0]


def _has_user_controlled_input(name: str, signature: str) -> bool:
    return (
        bool(_USER_ARG_RE.search(signature))
        or bool(_AMOUNT_ARG_RE.search(signature))
        or bool(_STAKE_FN_RE.search(name))
    )


def _reset_hit(name: str, signature: str, body: str) -> bool:
    if not _RESET_FN_RE.search(name):
        return False
    if not _has_user_controlled_input(name, signature):
        return False
    if not _RESET_WRITE_RE.search(body):
        return False
    return _CALLER_GATED_RE.search(body) is None


def _stake_overwrite_hit(name: str, signature: str, body: str) -> bool:
    if not _STAKE_FN_RE.search(name):
        return False
    if not _AMOUNT_ARG_RE.search(signature):
        return False
    if not (_OVERWRITE_ASSIGN_RE.search(body) or _OVERWRITE_INSERT_RE.search(body)):
        return False
    return _ACCUMULATE_PREVIOUS_RE.search(body) is None


def _shape_for(name: str, signature: str, body: str) -> str | None:
    if _reset_hit(name, signature, body):
        return "reward-state-reset-without-user-gate"
    if _stake_overwrite_hit(name, signature, body):
        return "staking-balance-overwrite-without-accumulation"
    return None


def _message(name: str, shape: str) -> str:
    if shape == "reward-state-reset-without-user-gate":
        detail = (
            "resets reward multiplier, reward index, or reward debt state "
            "from a public user-controlled flow without proving caller == user"
        )
    else:
        detail = (
            "overwrites staking balance with the new amount instead of "
            "accumulating the previous stake"
        )
    return (
        f"pub fn `{name}` {detail}; reward accounting can be skewed "
        f"({shape}, rewards-distribution-skew, Fire26 multiplier reset lift)."
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    if not _REWARD_CONTEXT_RE.search(source_nocomment(source)):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _REWARD_CONTEXT_RE.search(name + "\n" + body_nc):
            continue

        shape = _shape_for(name, _signature(fn, source), body_nc)
        if shape is None:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": _message(name, shape),
        })
    return hits
