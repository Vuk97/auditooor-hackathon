"""
rewards-delegate-grief-unbounded-recipients-fire39

verification_tier: tier-3-synthetic-taxonomy-anchored
attack_class: rewards-distribution-skew
context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
MCP receipt: .auditooor/memory_context_receipt.json
NOT_SUBMIT_READY
R40/R76/R80 caveat: detector hits are source-review candidates only, not proof.

Solidity recall detector for rewards-distribution-skew where public delegate,
referral, affiliate, or reward-recipient paths let a caller pad a reward-bearing
recipient set without a small cap, dedupe/domain guard, settlement, or
checkpoint. The detector also catches the sibling dh-laura shape where reward
math weights a claimant or pool by live balanceOf(address(this)) instead of a
tracked or snapshotted stake denominator.

Seeded only from confirmed recall misses and source refs:
- reports/detector_lift_fire38_20260605/post_priorities_solidity.md
- reference/patterns.dsl/delegate-grief-unbounded-recipients.yaml
- reference/patterns.dsl/dh-laura-reward-on-balanceOf-inflatable.yaml
- reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml
- detectors/wave17/delegate_unbounded_reward_recipients_fire27.py
- detectors/wave17/rewards_branch_asymmetry_fire38.py

This intentionally avoids the Fire38 branch-asymmetric-idempotency shape: an
unequal claimed, processed, or checkpointed branch alone is not enough. A hit
must involve either a delegate/referral recipient set or live balanceOf reward
weighting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-delegate-grief-unbounded-recipients-fire39"
DETECTOR_SEVERITY_DEFAULT = "Medium"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
ATTACK_CLASS = "rewards-distribution-skew"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    body_line: int


@dataclass
class LoopSlice:
    header: str
    body: str
    start: int
    end: int


@dataclass
class LoopTarget:
    loop_expr: str
    canonical_expr: str
    base: str
    index_var: str


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_REWARD_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|rewards?|emission\w*|incentive\w*|claimable\w*|"
    r"pending\w*|earned\w*|accrued\w*|accReward\w*|rewardDebt\w*|"
    r"rewardIndex\w*|rewardPer\w*|distribut\w*|harvest\w*)\b",
    re.IGNORECASE,
)
_DELEGATE_RECIPIENT_CONTEXT_RE = re.compile(
    r"\b(?:delegat\w*|referr\w*|referral\w*|referee\w*|affiliate\w*|"
    r"recipient\w*|beneficiar\w*|payee\w*|receiver\w*)\b",
    re.IGNORECASE,
)
_DELEGATE_OR_REFERRAL_SURFACE_RE = re.compile(
    r"\b(?:delegat\w*|referr\w*|referral\w*|referee\w*|affiliate\w*|"
    r"rewardRecipients?|payoutRecipients?|beneficiaries|payees)\b",
    re.IGNORECASE,
)
_LIST_NAME_RE = re.compile(
    r"(?:delegate|delegates|delegatee|delegator|referr|referral|referee|"
    r"affiliate|recipient|beneficiar|payee|receiver|rewardRecipient|"
    r"payoutRecipient|accounts?|users?)",
    re.IGNORECASE,
)
_ADMIN_GUARD_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyRole|"
    r"onlyKeeper|onlyDistributor|requiresAuth|adminOnly|governanceOnly)\b|"
    r"\bhasRole\s*\(",
    re.IGNORECASE,
)
_SAFE_BOUNDARY_RE = re.compile(
    r"\b(?:_?settle[A-Za-z0-9_]*(?:Reward|Rewards|Account|User)?|"
    r"_?checkpoint[A-Za-z0-9_]*(?:Reward|Rewards|Account|User|Stake|"
    r"Delegate|Index)?|_?sync[A-Za-z0-9_]*(?:Reward|Rewards|Index)?|"
    r"_?update[A-Za-z0-9_]*(?:Reward|Rewards|Index|Accumulator)|"
    r"_?consume[A-Za-z0-9_]*|_?mark[A-Za-z0-9_]*(?:Claimed|Processed)|"
    r"domainSeparator|domainBound|bindDomain|registeredRecipient|"
    r"allowedRecipient|validRecipient|activeRecipient|whitelist|allowlist|"
    r"recipientSet\s*\.\s*contains|seenRecipient|recipientSeen|"
    r"claimed|processed|consumed)\b",
    re.IGNORECASE,
)

_ARRAY_PARAM_RE = re.compile(
    r"\b(?:address(?:\s+payable)?|[A-Za-z_][A-Za-z0-9_]*)\s*\[\]\s*"
    r"(?:calldata|memory|storage)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_STORAGE_ALIAS_RE = re.compile(
    r"\b(?:address(?:\s+payable)?|[A-Za-z_][A-Za-z0-9_]*)\s*\[\]\s+"
    r"storage\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)*)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_LENGTH_ALIAS_RE = re.compile(
    r"\b(?:uint(?:256)?|int(?:256)?|var)?\s*"
    r"(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)*)"
    r"\s*\.\s*length\s*;",
    re.IGNORECASE | re.DOTALL,
)
_LENGTH_EXPR_RE = re.compile(
    r"(?P<expr>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)*)\s*\.\s*length\b",
    re.IGNORECASE,
)
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(", re.IGNORECASE)
_FOR_INDEX_RE = re.compile(
    r"^\s*(?:uint(?:256)?|int(?:256)?)?\s*(?P<idx>[A-Za-z_][A-Za-z0-9_]*)\s*=",
    re.IGNORECASE,
)
_COMPARE_INDEX_RE = re.compile(
    r"\b(?P<idx>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<|<=)\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)*\.length|"
    r"[A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)

_ACCOUNTING_SLOT_RE = (
    r"(?:pendingRewards?|claimableRewards?|accruedRewards?|earnedRewards?|"
    r"unclaimedRewards?|rewardDebt|rewardDebts|rewardBalances?|"
    r"rewardShares?|rewardWeight|rewardWeights|recipientRewardDebt|"
    r"referralRewards?|referrerRewards?|affiliateRewards?|"
    r"delegateReward\w*|delegatedReward\w*|rewardCheckpoints?|"
    r"delegateCheckpoints?|checkpoint\w*|weightOf|pointsOf)"
)
_ACCOUNTING_CALL_RE = re.compile(
    r"\b_?(?:checkpoint|writeCheckpoint|updateReward|accrueReward|"
    r"creditReward|recordReward|distributeReward|moveDelegates?|"
    r"checkpointDelegate|updateDelegate|creditReferral|recordReferral)"
    r"[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)

_LIVE_BALANCE_RE = re.compile(
    r"\b(?:(?P<token>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*)?balanceOf\s*\(\s*"
    r"(?P<subject>address\s*\(\s*this\s*\)|this|pool|rewardPool|stakingPool|"
    r"recipient|receiver|user|account|msg\.sender)\s*\)",
    re.IGNORECASE,
)
_BALANCE_ASSIGN_RE = re.compile(
    r"\b(?:uint(?:256)?\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?balanceOf\s*\(\s*"
    r"(?:address\s*\(\s*this\s*\)|this|pool|rewardPool|stakingPool|"
    r"recipient|receiver|user|account|msg\.sender)\s*\))\s*;",
    re.IGNORECASE | re.DOTALL,
)
_TRACKED_OR_SNAPSHOT_DENOMINATOR_RE = re.compile(
    r"\b(?:totalStaked|totalStake|totalDeposits|totalDeposit|stakedAmount|"
    r"_totalDeposited|trackedStake|trackedBalance|eligibleSupply|"
    r"rewardSupplySnapshot|balanceSnapshot|snapshotBalance|snapshotSupply|"
    r"checkpointSupply|sharesAt|stakeAt|supplyAt|lockedBalance|"
    r"Math\s*\.\s*mulDiv|FullMath\s*\.\s*mulDiv|mulDiv)\b",
    re.IGNORECASE,
)
_REWARD_FORMULA_AFTER_RE = re.compile(
    r"\b(?:return|reward\w*|pending\w*|claimable\w*|earned\w*|"
    r"accReward\w*|rewardPer\w*)\b[^;{}]{0,360}(?:/|\*)",
    re.IGNORECASE | re.DOTALL,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    i = open_pos + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    close_brace = _find_matching_delimiter(source, open_brace, "{", "}")
    if close_brace < 0:
        return None, open_brace
    return source[open_brace + 1 : close_brace], close_brace + 1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        j = close_paren + 1
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, close_paren + 1)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start() : body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _loops(body: str) -> list[LoopSlice]:
    out: list[LoopSlice] = []
    pos = 0
    while True:
        match = _LOOP_RE.search(body, pos)
        if match is None:
            break
        open_paren = body.find("(", match.start())
        close_paren = _find_matching_delimiter(body, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue
        block_start = close_paren + 1
        while block_start < len(body) and body[block_start].isspace():
            block_start += 1
        if block_start >= len(body) or body[block_start] != "{":
            pos = close_paren + 1
            continue
        loop_body, end_pos = _extract_balanced_block(body, block_start)
        if loop_body is None:
            pos = block_start + 1
            continue
        out.append(
            LoopSlice(
                header=body[open_paren + 1 : close_paren],
                body=loop_body,
                start=match.start(),
                end=end_pos,
            )
        )
        pos = end_pos
    return out


def _line_for_body_pos(fn: FunctionSlice, pos: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, pos))


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _base_identifier(expr: str) -> str:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", expr or "")
    return match.group(1) if match else (expr or "").strip()


def _dynamic_array_params(header: str) -> set[str]:
    return {
        match.group("name")
        for match in _ARRAY_PARAM_RE.finditer(header)
        if _LIST_NAME_RE.search(match.group("name"))
    }


def _storage_aliases(body: str) -> dict[str, str]:
    return {
        match.group("alias"): match.group("expr").strip()
        for match in _STORAGE_ALIAS_RE.finditer(body)
    }


def _length_aliases(body: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in _LENGTH_ALIAS_RE.finditer(body):
        alias = match.group("alias")
        if alias not in {"uint", "uint256", "int", "int256"}:
            aliases[alias] = match.group("expr").strip()
    return aliases


def _index_var(header: str) -> str:
    for_part = header.split(";", 1)[0]
    match = _FOR_INDEX_RE.search(for_part)
    if match is not None:
        return match.group("idx")
    match = _COMPARE_INDEX_RE.search(header)
    return match.group("idx") if match is not None else "i"


def _loop_targets(loop: LoopSlice, aliases: dict[str, str], lengths: dict[str, str]) -> list[LoopTarget]:
    targets: list[LoopTarget] = []
    idx = _index_var(loop.header)
    for match in _LENGTH_EXPR_RE.finditer(loop.header):
        expr = match.group("expr").strip()
        canonical = aliases.get(expr, expr)
        targets.append(
            LoopTarget(
                loop_expr=expr,
                canonical_expr=canonical,
                base=_base_identifier(canonical),
                index_var=idx,
            )
        )
    for alias, expr in lengths.items():
        if re.search(rf"\b{re.escape(alias)}\b", loop.header):
            canonical = aliases.get(expr, expr)
            targets.append(
                LoopTarget(
                    loop_expr=expr,
                    canonical_expr=canonical,
                    base=_base_identifier(canonical),
                    index_var=idx,
                )
            )

    deduped: list[LoopTarget] = []
    seen: set[tuple[str, str, str]] = set()
    for target in targets:
        key = (target.loop_expr, target.canonical_expr, target.index_var)
        if key not in seen:
            seen.add(key)
            deduped.append(target)
    return deduped


def _is_fixed_array_declared(source: str, base: str) -> bool:
    if not base:
        return False
    return bool(
        re.search(
            rf"\b(?:address(?:\s+payable)?|[A-Za-z_][A-Za-z0-9_]*)\s*"
            rf"\[\s*\d+\s*\]\s*(?:public|private|internal|external)?\s*"
            rf"{re.escape(base)}\b",
            source,
            re.IGNORECASE,
        )
    )


def _has_cap_guard(fn: FunctionSlice, loop: LoopSlice, target: LoopTarget) -> bool:
    prefix = fn.body[: loop.start]
    checked = _compact(f"{fn.header}\n{prefix}\n{loop.header}\n{loop.body[:220]}")
    exprs = {
        _compact(target.loop_expr),
        _compact(target.canonical_expr),
        target.base,
    }
    for expr in exprs:
        if not expr:
            continue
        length = rf"{re.escape(expr)}\.length"
        if re.search(rf"require\({length}(?:<=|<)[^)]+\)", checked, re.IGNORECASE):
            return True
        if re.search(rf"if\({length}(?:>|>=)[^)]+\)(?:\{{)?revert", checked, re.IGNORECASE):
            return True
        if re.search(rf"revert[A-Za-z0-9_]*\([^;]*{length}", checked, re.IGNORECASE):
            return True
        if re.search(rf"(?:min|Math\.min)\({length},[^)]+\)", checked, re.IGNORECASE):
            return True
        if re.search(rf"(?:min|Math\.min)\([^)]+,{length}\)", checked, re.IGNORECASE):
            return True

    for alias in _length_aliases(prefix):
        if re.search(rf"require\({re.escape(alias)}(?:<=|<)[^)]+\)", checked, re.IGNORECASE):
            return True
        if re.search(rf"if\({re.escape(alias)}(?:>|>=)[^)]+\)(?:\{{)?revert", checked, re.IGNORECASE):
            return True
    return False


def _has_safe_boundary(fn: FunctionSlice, loop: LoopSlice) -> bool:
    prefix = fn.body[: loop.start]
    loop_prefix = loop.body[:360]
    return bool(_SAFE_BOUNDARY_RE.search(f"{fn.header}\n{prefix}\n{loop_prefix}"))


def _is_user_controlled(target: LoopTarget, dynamic_params: set[str]) -> bool:
    loop_base = _base_identifier(target.loop_expr)
    compact_expr = _compact(target.canonical_expr)
    if loop_base in dynamic_params or target.base in dynamic_params:
        return True
    if "msg.sender" in compact_expr:
        return True
    return False


def _element_names(loop: LoopSlice, target: LoopTarget) -> set[str]:
    names: set[str] = set()
    compact_body = _compact(loop.body)
    index = re.escape(target.index_var)
    exprs = {_compact(target.loop_expr), _compact(target.canonical_expr)}

    for expr in exprs:
        if not expr:
            continue
        indexed = rf"{re.escape(expr)}\[{index}\]"
        assign_re = re.compile(
            rf"\b(?:address(?:payable)?|[A-Za-z_][A-Za-z0-9_]*)"
            rf"(?P<name>[A-Za-z_][A-Za-z0-9_]*)={indexed}",
            re.IGNORECASE,
        )
        for match in assign_re.finditer(compact_body):
            names.add(match.group("name"))
        if re.search(indexed, compact_body):
            names.add(f"{expr}[{target.index_var}]")
    return names


def _accounting_targets(loop: LoopSlice, target: LoopTarget) -> bool:
    if not _REWARD_CONTEXT_RE.search(loop.body):
        return False
    candidate_names = _element_names(loop, target)
    if not candidate_names:
        return False

    compact_body = _compact(loop.body)
    for name in candidate_names:
        if "[" in name:
            target_pat = re.escape(_compact(name))
            if re.search(
                rf"{_ACCOUNTING_SLOT_RE}\[{target_pat}\](?:=|\+=|-=|\.|\[)",
                compact_body,
                re.IGNORECASE,
            ):
                return True
            continue

        name_pat = rf"\b{re.escape(name)}\b"
        slot_re = re.compile(
            rf"\b{_ACCOUNTING_SLOT_RE}\s*\[\s*{name_pat}\s*\]\s*(?:=|\+=|-=|\.|\[)",
            re.IGNORECASE | re.DOTALL,
        )
        call_re = re.compile(
            rf"{_ACCOUNTING_CALL_RE.pattern}[^;{{}}]*{name_pat}",
            re.IGNORECASE | re.DOTALL,
        )
        if slot_re.search(loop.body) or call_re.search(loop.body):
            return True
    return False


def _delegate_recipient_loop(
    source: str,
    fn: FunctionSlice,
) -> tuple[LoopSlice, LoopTarget, str] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header) or _VIEW_OR_PURE_RE.search(fn.header):
        return None
    if _ADMIN_GUARD_RE.search(fn.header):
        return None
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    if not (_REWARD_CONTEXT_RE.search(text) and _DELEGATE_RECIPIENT_CONTEXT_RE.search(text)):
        return None
    if not _DELEGATE_OR_REFERRAL_SURFACE_RE.search(text[:1800]):
        return None

    dynamic_params = _dynamic_array_params(fn.header)
    aliases = _storage_aliases(fn.body)
    lengths = _length_aliases(fn.body)
    for loop in _loops(fn.body):
        for target in _loop_targets(loop, aliases, lengths):
            if not _LIST_NAME_RE.search(target.base):
                continue
            if _is_fixed_array_declared(source, target.base):
                continue
            if not _is_user_controlled(target, dynamic_params):
                continue
            if _has_cap_guard(fn, loop, target):
                continue
            if _has_safe_boundary(fn, loop):
                continue
            if not _accounting_targets(loop, target):
                continue
            reason = (
                f"iterates caller-controlled `{target.canonical_expr}` without a small cap, "
                "dedupe/domain guard, settlement, or checkpoint while updating reward "
                "accounting for each delegate or recipient"
            )
            return loop, target, reason
    return None


def _has_reward_formula_using_balance(fn: FunctionSlice, balance_match: re.Match[str]) -> bool:
    var_name = balance_match.groupdict().get("var")
    tail = fn.body[balance_match.end() : balance_match.end() + 900]
    if var_name:
        return bool(
            re.search(
                rf"\b(?:return|reward\w*|pending\w*|claimable\w*|earned\w*)\b"
                rf"[^;{{}}]{{0,520}}\b{re.escape(var_name)}\b",
                tail,
                re.IGNORECASE | re.DOTALL,
            )
        )
    return bool(_REWARD_FORMULA_AFTER_RE.search(fn.body[balance_match.start() : balance_match.start() + 700]))


def _live_balance_reward_weight(source: str, fn: FunctionSlice) -> re.Match[str] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return None
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    if not _REWARD_CONTEXT_RE.search(text):
        return None
    if _TRACKED_OR_SNAPSHOT_DENOMINATOR_RE.search(text) or _TRACKED_OR_SNAPSHOT_DENOMINATOR_RE.search(source):
        return None

    for match in _BALANCE_ASSIGN_RE.finditer(fn.body):
        if _has_reward_formula_using_balance(fn, match):
            return match
    for match in _LIVE_BALANCE_RE.finditer(fn.body):
        if _has_reward_formula_using_balance(fn, match):
            return match
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not (_REWARD_CONTEXT_RE.search(clean) and (_DELEGATE_RECIPIENT_CONTEXT_RE.search(clean) or _LIVE_BALANCE_RE.search(clean))):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        loop_result = _delegate_recipient_loop(clean, fn)
        if loop_result is not None:
            loop, _target, reason = loop_result
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for_body_pos(fn, loop.start),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` has reward delegate recipient skew: {reason}. "
                        "Cap and dedupe user-expanded delegate/referral recipient "
                        "sets, bind recipients to an approved domain, or checkpoint "
                        "reward state before iterating attacker-padded lists."
                    ),
                )
            )
            continue

        balance_result = _live_balance_reward_weight(clean, fn)
        if balance_result is not None:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for_body_pos(fn, balance_result.start()),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` has live balanceOf reward weighting: reward "
                        "math reads balanceOf(address(this)), pool, recipient, or user "
                        "balance without a tracked stake denominator or reward "
                        "snapshot. Direct token transfers or recipient balance "
                        "inflation can skew reward distribution."
                    ),
                )
            )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "scan",
]
