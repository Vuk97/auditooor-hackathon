"""
reward_overwrite_or_recursive_amplification_fire17.py

Fire17 same-class lift for Rust rewards-distribution-skew misses.

Flags three bounded reward-skew shapes:
- reward, beneficiary, checkpoint, or rate slots overwritten without a
  preserve or monotonic guard
- rewards computed from raw balance times reward-per-share without
  source-principal or wrapper-pool exclusion
- caller-supplied withdrawal credential or reward sink written without
  authorization and current-slot invariant checks

Confirmed seed misses:
- r94-loop-htlc-reward-overwrite-positive
- r94-loop-incentivized-erc20-recursive-liquidity-reward-amplification-positive
- r94-loop-restaking-node-operator-withdraw-credentials-overwrite-positive

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
)


_REWARD_OR_SINK_CONTEXT_RE = re.compile(
    r"(?i)(reward|rewards|incentive|emission|beneficiary|checkpoint|"
    r"withdraw_?credentials|withdrawal_?credentials|reward_?rate|"
    r"reward_?index|reward_?per_?share|acc_?reward)"
)

_OVERWRITE_FN_RE = re.compile(
    r"(?i)(lock_?reward|set_?reward|update_?reward|set_?beneficiary|"
    r"update_?beneficiary|set_?checkpoint|set_?reward_?rate|"
    r"update_?reward_?rate|stake|register_?validator|delegate_?to_?operator|"
    r"set_?withdraw(?:al)?_?credentials|configure_?credentials)"
)

_OVERWRITE_WRITE_RE = re.compile(
    r"(?is)("
    r"\.\s*(?:reward|rewards|beneficiary|checkpoint|reward_rate|"
    r"reward_index|withdraw_credentials|withdrawal_credentials)\s*=\s*"
    r"|"
    r"(?:store|save|set|write)_(?:reward|rewards|beneficiary|checkpoint|"
    r"reward_rate|withdraw_?credentials|withdrawal_?credentials)\s*\("
    r"|"
    r"\.\s*set\s*\([^)]*(?:reward|beneficiary|checkpoint|"
    r"withdraw_?credentials|withdrawal_?credentials)"
    r")"
)

_OVERWRITE_GUARD_RE = re.compile(
    r"(?is)("
    r"(?:previous|prev|existing|current)_(?:reward|beneficiary|checkpoint|"
    r"reward_rate|creds|credentials|withdraw_?credentials|"
    r"withdrawal_?credentials)"
    r"|"
    r"\.\s*(?:reward|rewards|beneficiary|checkpoint|reward_rate|"
    r"withdraw_credentials|withdrawal_credentials)\s*(?:==|!=)\s*"
    r"(?:0|None|\[\s*0|self_?address|vault|admin)"
    r"|"
    r"\.\s*(?:reward|rewards|beneficiary|checkpoint|"
    r"withdraw_credentials|withdrawal_credentials)\s*\.\s*"
    r"(?:is_none|is_zero)"
    r"|"
    r"require!?\s*\([^)]*(?:reward|beneficiary|checkpoint|"
    r"withdraw_?credentials|withdrawal_?credentials)[^)]*"
    r"(?:==|!=|is_none|is_zero)"
    r"|"
    r"assert!?\s*\([^)]*(?:reward|beneficiary|checkpoint|"
    r"withdraw_?credentials|withdrawal_?credentials)[^)]*"
    r"(?:==|!=|is_none|is_zero)"
    r"|"
    r"saturating_add\s*\(|checked_add\s*\("
    r")"
)

_AUTH_GUARD_RE = re.compile(
    r"(?i)(require_auth|only_owner|only_admin|ensure_root|ensure_signed|"
    r"has_role|assert_owner|assert_admin|admin\.require_auth|"
    r"owner\.require_auth|vault\.require_auth)"
)

_RECURSIVE_FN_RE = re.compile(
    r"(?i)(pending_?reward|pending_?rewards|claim_?reward|"
    r"claim_?rewards|harvest|compute_?rewards|accrue_?reward|"
    r"reward_?of|update_?reward)"
)

_RPS_COMPUTE_RE = re.compile(
    r"(?is)("
    r"balance_of\s*\([^)]*\)\s*\*\s*[A-Za-z0-9_\.]*"
    r"(?:acc_?reward|reward_?per_?share|reward_?index)"
    r"|"
    r"\b(?:bal|balance|shares|user_balance)[A-Za-z0-9_]*\s*\*\s*"
    r"[A-Za-z0-9_\.]*(?:acc_?reward|reward_?per_?share|reward_?index)"
    r"|"
    r"[A-Za-z0-9_\.]*(?:acc_?reward|reward_?per_?share|reward_?index)"
    r"\s*\*\s*\b(?:bal|balance|shares|user_balance)[A-Za-z0-9_]*"
    r"|"
    r"position\s*\.\s*balance\s*\*\s*pool\s*\.\s*reward_per_token_stored"
    r")"
)

_RECURSION_GUARD_RE = re.compile(
    r"(?i)(is_pool_or_vault|is_pool|is_vault|is_contract|blacklist|"
    r"pool_address_registry|tracked_deposit_balance|deposit_principal|"
    r"source_position|underlying_source|yield_bearing_tokens|"
    r"is_yield_bearing|snapshot_at_deposit|user_deposit_ledger|"
    r"principal_balance|non_recursive|recursive_deposit_blocked)"
)

_CALLER_SINK_RE = re.compile(
    r"(?is)("
    r"(?:save|store|set|write)_(?:withdraw_?credentials|"
    r"withdrawal_?credentials)\s*\([^)]*(?:withdraw_?credentials|"
    r"withdrawal_?credentials)"
    r"|"
    r"(?:credit|mint|transfer|pay|send)_[A-Za-z0-9_]*\s*\([^)]*"
    r"(?:reward_?recipient|beneficiary|recipient|sink)"
    r")"
)

_SINK_GUARD_RE = re.compile(
    r"(?is)("
    r"require_auth|only_owner|only_admin|ensure_root|has_role|"
    r"allowed_(?:recipient|beneficiary|sink)|registered_(?:recipient|"
    r"beneficiary|sink)|recipient_registry|beneficiary_registry|"
    r"current_?creds\s*(?:==|!=)|current_?credentials\s*(?:==|!=)|"
    r"load_current_credentials|existing_(?:recipient|beneficiary|sink)"
    r")"
)


def _overwrite_hit(name: str, body: str) -> bool:
    if not _OVERWRITE_FN_RE.search(name):
        return False
    if not _REWARD_OR_SINK_CONTEXT_RE.search(body):
        return False
    if not _OVERWRITE_WRITE_RE.search(body):
        return False
    if _OVERWRITE_GUARD_RE.search(body):
        return False
    if "withdraw" in body.lower() and _AUTH_GUARD_RE.search(body):
        return False
    return True


def _recursive_reward_hit(name: str, body: str) -> bool:
    if not _RECURSIVE_FN_RE.search(name):
        return False
    if not _RPS_COMPUTE_RE.search(body):
        return False
    return _RECURSION_GUARD_RE.search(body) is None


def _caller_sink_hit(body: str) -> bool:
    if not _CALLER_SINK_RE.search(body):
        return False
    return _SINK_GUARD_RE.search(body) is None


def _shape_for(name: str, body: str) -> str | None:
    if _caller_sink_hit(body):
        return "caller-controlled-sink"
    if _overwrite_hit(name, body):
        return "unguarded-overwrite"
    if _recursive_reward_hit(name, body):
        return "recursive-amplification"
    return None


def _message(name: str, shape: str) -> str:
    if shape == "caller-controlled-sink":
        detail = (
            "writes caller-supplied withdrawal credentials or reward sink "
            "without authorization and current-slot invariant checks"
        )
    elif shape == "unguarded-overwrite":
        detail = (
            "overwrites reward, beneficiary, checkpoint, rate, or credential "
            "state without preserving the previous value or proving monotonicity"
        )
    else:
        detail = (
            "computes rewards from raw balance times reward-per-share without "
            "source-principal tracking or wrapper-pool exclusion"
        )
    return (
        f"pub fn `{name}` {detail}; reward allocation can be skewed "
        f"(rewards-distribution-skew, Fire17 overwrite-or-recursive lift)."
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
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
        if not _REWARD_OR_SINK_CONTEXT_RE.search(name + "\n" + body_nc):
            continue

        shape = _shape_for(name, body_nc)
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
