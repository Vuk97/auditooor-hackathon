"""
restaking_reward_queue_or_operator_skew_fire19.py

Fire19 same-class lift for Rust rewards-distribution-skew misses in
restaking operator and strategy accounting.

Flags three bounded shapes:
- operator heap allocation uses removed or tombstoned entries without a
  tombstone or utilization guard
- operator self-undelegation changes delegation state or LRT payout before
  participant reward or rate settlement
- strategy cap is zeroed without synchronizing total shares and the
  withdrawal queue

Seed misses:
- r94-loop-restaking-operator-heap-removed-id-stale-divzero-positive
- r94-loop-restaking-operator-self-undelegate-lrt-rate-manipulation-positive
- r94-loop-restaking-strategy-cap-zero-skips-shares-queue-sync-positive

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
)


_RESTAKING_CONTEXT_RE = re.compile(
    r"(?i)(restak|operator|delegat|undelegat|strategy|lrt|liquid_?restak|"
    r"withdrawal_?queue|reward|shares|cap|heap|utilization)"
)

_HEAP_FN_RE = re.compile(
    r"(?i)(allocate|rebalance|deposit|withdraw|operator|delegate|distribute)"
)

_HEAP_USAGE_RE = re.compile(
    r"(?is)(operator_?heap|load_operator_heap|heap)\s*\([^)]*\)?[\s\S]{0,900}?"
    r"\bfor\s+[A-Za-z0-9_]+\s+in\s+[A-Za-z0-9_\.]+\.iter\s*\(\s*\)"
)

_HEAP_DIV_RE = re.compile(
    r"(?is)/\s*(?:[A-Za-z0-9_]+\.)?(?:utilization|active_?stake|weight)"
)

_HEAP_TOMBSTONE_GUARD_RE = re.compile(
    r"(?is)("
    r"operator_?id\s*(?:==|!=)\s*0|"
    r"(?:is_)?(?:removed|active|inactive|tombstone)|"
    r"utilization\s*(?:==|!=|>|>=)\s*0|"
    r"checked_div\s*\(|"
    r"filter\s*\([^)]*(?:operator_?id|removed|active|utilization)"
    r")"
)

_UNDELEGATE_FN_RE = re.compile(r"(?i)(undelegate|unbond|remove_?delegation)")

_DELEGATION_MUTATION_RE = re.compile(
    r"(?is)\b(remove_?delegation|undelegate|delegations?\s*\.\s*remove|"
    r"delegations?\s*\.\s*insert|operator_?set\s*\.\s*remove)\s*\("
)

_LRT_RATE_OR_PAYOUT_RE = re.compile(
    r"(?i)(pay_?out_?lrt|lrt|exchange_?rate|reward|rewards|reward_?rate|"
    r"claimable|payout|mint_?shares|burn_?shares)"
)

_SETTLE_CALL_RE = re.compile(
    r"(?is)\b("
    r"settle_(?:participant|account|user|operator|delegation|reward|"
    r"rewards|reward_index|reward_debt|lrt_rate|exchange_rate|shares)|"
    r"checkpoint_(?:participant|account|user|operator|delegation|reward|"
    r"rewards|reward_index|shares)|"
    r"sync_(?:participant|account|user|operator|delegation|reward|"
    r"rewards|reward_index|shares)|"
    r"accrue_(?:participant|account|user|operator|reward|rewards)|"
    r"update_(?:participant|account|user|operator|reward|rewards|"
    r"reward_index|exchange_rate|lrt_rate)"
    r")\s*\("
)

_SELF_UNDELEGATE_GUARD_RE = re.compile(
    r"(?is)("
    r"is_operator\s*\([^;]{0,220}(?:caller|sender|staker)|"
    r"(?:operator|caller|sender)[^;]{0,220}cannot[^;]{0,80}"
    r"(?:self|undelegate)|"
    r"(?:assert|ensure|require)!?\s*\([^;]{0,260}"
    r"(?:caller|sender|operator|staker)[^;]{0,260}"
    r"(?:!=|==|is_operator|not_operator)|"
    r"only_(?:admin|governance|operator)|"
    r"require_auth\s*\("
    r")"
)

_CAP_FN_RE = re.compile(r"(?i)(set_?strategy_?cap|update_?strategy_?cap|cap)")

_CAP_ZERO_RE = re.compile(r"(?is)(?:\.\s*)?cap\s*=\s*0\b")

_STRATEGY_SHARE_OR_QUEUE_RE = re.compile(
    r"(?i)(total_?shares|withdrawal_?queue|queued_?shares|strategy_?shares)"
)

_SHARE_SYNC_RE = re.compile(
    r"(?is)\b(update|sync|recompute|recalculate)_(?:total_)?shares\s*\("
)

_QUEUE_SYNC_RE = re.compile(
    r"(?is)\b(update|sync|rebuild|recompute)_(?:withdrawal_)?queue\s*\("
)


def _settles_before(body: str, pos: int) -> bool:
    settle = _SETTLE_CALL_RE.search(body)
    return bool(settle and settle.start() < pos)


def _operator_heap_hit(name: str, body: str) -> bool:
    if not _HEAP_FN_RE.search(name):
        return False
    if not _HEAP_USAGE_RE.search(body):
        return False
    if not _HEAP_DIV_RE.search(body):
        return False
    return _HEAP_TOMBSTONE_GUARD_RE.search(body) is None


def _self_undelegate_hit(name: str, body: str) -> bool:
    if not _UNDELEGATE_FN_RE.search(name):
        return False
    mutation = _DELEGATION_MUTATION_RE.search(body)
    if mutation is None:
        return False
    if not _LRT_RATE_OR_PAYOUT_RE.search(body):
        return False
    if _SELF_UNDELEGATE_GUARD_RE.search(body):
        return False
    return not _settles_before(body, mutation.start())


def _cap_zero_hit(name: str, body: str, source_text: str) -> bool:
    if not _CAP_FN_RE.search(name):
        return False
    cap = _CAP_ZERO_RE.search(body)
    if cap is None:
        return False
    if not _STRATEGY_SHARE_OR_QUEUE_RE.search(source_text):
        return False
    if _settles_before(body, cap.start()):
        return False
    return not (_SHARE_SYNC_RE.search(body) and _QUEUE_SYNC_RE.search(body))


def _shape_for(name: str, body: str, source_text: str) -> str | None:
    if _operator_heap_hit(name, body):
        return "operator-heap-tombstone"
    if _self_undelegate_hit(name, body):
        return "self-undelegate-before-settle"
    if _cap_zero_hit(name, body, source_text):
        return "cap-zero-queue-desync"
    return None


def _message(name: str, shape: str) -> str:
    if shape == "operator-heap-tombstone":
        detail = (
            "allocates across an operator heap without skipping removed "
            "operators or guarding zero utilization"
        )
    elif shape == "self-undelegate-before-settle":
        detail = (
            "mutates delegation membership or LRT payout before participant "
            "reward or exchange-rate settlement"
        )
    else:
        detail = (
            "zeros a restaking strategy cap without synchronizing total "
            "shares and withdrawal queue membership"
        )
    return (
        f"pub fn `{name}` {detail}; restaking reward or queue accounting "
        f"can be skewed (rewards-distribution-skew, Fire19 restaking lift)."
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    source_text = source_nocomment(source)
    if not _RESTAKING_CONTEXT_RE.search(source_text):
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
        if not _RESTAKING_CONTEXT_RE.search(name + "\n" + body_nc):
            continue

        shape = _shape_for(name, body_nc, source_text)
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
