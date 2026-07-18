"""
rewards-distribution-skew-fire21

Solidity same-class recall detector for confirmed rewards-distribution-skew
misses: branch-asymmetric idempotency flags, relayer rewards paid after failed
dispatch, and bulk burn reward math calculated against a stale total supply
denominator.

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-distribution-skew-fire21"
DETECTOR_SEVERITY_DEFAULT = "Medium"


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


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_CONTEXT_RE = re.compile(
    r"\b(reward\w*|claim\w*|relayer\w*|dispatch\w*|refund\w*|"
    r"burn\w*|redeem\w*|withdraw\w*|totalSupply|_totalSupply|processed|"
    r"consumed|paid|settled|claimed)\b",
    re.IGNORECASE,
)
_IF_ELSE_BLOCK_RE = re.compile(
    r"(?:\bif\s*\((?P<cond>[^)]*)\)|\belse(?:\s+if\s*\((?P<elif>[^)]*)\))?)"
    r"\s*\{(?P<body>[^{}]*)\}",
    re.DOTALL,
)
_FLAG_WRITE_RE = re.compile(
    r"\b(?P<flag>[A-Za-z_][A-Za-z0-9_]*(?:Claimed|Processed|Consumed|"
    r"Redeemed|Paid|Settled|Withdrawn|Dispatched|Finalized)|claimed|"
    r"processed|consumed|redeemed|paid|settled|withdrawn|dispatched|"
    r"finalized)\b\s*(?:\[[^\]]+\]\s*)*(?:=|:=)\s*true\b|"
    r"\b(?:toggle|mark|set)[A-Z][A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)
_REWARD_SIDE_EFFECT_RE = re.compile(
    r"\b(?:safeTransfer|transfer|sendValue|mint|_mint|claimReward|"
    r"creditReward|payReward|payable|reward\w*\s*(?:=|\+=)|"
    r"\w*reward\w*\s*(?:\[[^\]]+\]\s*)?(?:=|\+=)|rebate|"
    r"bounty|refund)",
    re.IGNORECASE,
)
_SYMMETRIC_BRANCH_HINT_RE = re.compile(
    r"\b(?:markAllBranchesProcessed|checkpointBothBranches|symmetric|"
    r"commonFinalize|_markProcessed)\s*\(",
    re.IGNORECASE,
)

_DISPATCH_FAILURE_RE = re.compile(
    r"\btry\b[\s\S]{0,2600}?\bcatch\b(?:\s*\([^)]*\))?\s*\{[\s\S]{0,650}?"
    r"\bsuccess\s*=\s*false\b",
    re.IGNORECASE,
)
_CATCH_REVERT_RE = re.compile(
    r"\bcatch\b(?:\s*\([^)]*\))?\s*\{[^{}]*(?:revert\s*\(|require\s*\(\s*false\b)",
    re.IGNORECASE | re.DOTALL,
)
_RELAYER_PAYOUT_RE = re.compile(
    r"\b(?:safeNativeTransfer|safeTransferETH|sendValue|transfer)\s*\("
    r"[^;{}]*(?:msg\.sender|relayer)|"
    r"\bpayable\s*\(\s*(?:msg\.sender|relayer)\s*\)\s*\.\s*(?:transfer|send)\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:\s*[^}]*\}\s*\([^;{}]*(?:msg\.sender|relayer)|"
    r"\brelayerRewards\s*\[\s*(?:msg\.sender|relayer)\s*\]\s*\+=",
    re.IGNORECASE | re.DOTALL,
)
_SUCCESS_GATED_PAYOUT_RE = re.compile(
    r"\bif\s*\(\s*success\s*\)\s*\{[^{}]*(?:safeNativeTransfer|"
    r"safeTransferETH|sendValue|transfer|payable\s*\(|relayerRewards\s*\[|"
    r"\.call\s*\{\s*value\s*:)",
    re.IGNORECASE | re.DOTALL,
)
_REQUIRE_SUCCESS_RE = re.compile(r"\brequire\s*\(\s*success\s*[,)]", re.IGNORECASE)

_BULK_BURN_NAME_RE = re.compile(
    r"(?:bulk|batch|multi|many).*(?:burn|redeem|withdraw)|"
    r"(?:burn|redeem|withdraw).*(?:bulk|batch|multi|many)",
    re.IGNORECASE,
)
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(", re.IGNORECASE)
_SUPPLY_SNAPSHOT_RE = re.compile(
    r"\b(?:uint(?:256)?\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Supply|Denominator|supply|denominator|Total|total|Before|before)"
    r"[A-Za-z0-9_]*)\s*=\s*(?:totalSupply\s*\(\s*\)|totalSupply|_totalSupply)\b"
)
_REWARD_CALC_PREFIX_RE = (
    r"\b(?:reward\w*|claimable\w*|payout\w*|share\w*|amountOut)\b"
    r"\s*(?:\[[^\]]+\]\s*)?(?:=|\+=)\s*[^;]*\b"
)
_BURN_OR_SUPPLY_DECREMENT_RE = re.compile(
    r"\b(?:_burn|burn)\s*\(|\b(?:totalSupply|_totalSupply)\s*-=",
    re.IGNORECASE,
)
_SUPPLY_CHECKPOINT_RE = re.compile(
    r"\b(?:checkpointTotalSupply|_checkpointTotalSupply|checkpointSupply|"
    r"_checkpointSupply|postBurnSupply|supplyAfterBurn|afterBurnSupply|"
    r"remainingSupply|supplyAfter|totalSupplyAfter)\b",
    re.IGNORECASE,
)
_DENOMINATOR_BRANCH_RE = re.compile(
    r"\b(?:_burn|burn)\s*\(|\b(?:totalSupply|_totalSupply)\s*(?:-=|=)",
    re.IGNORECASE,
)
_BRANCH_REWARD_DENOMINATOR_RE = re.compile(
    r"\b(?:\w*reward\w*|claimable\w*|payout\w*)\b\s*(?:\[[^\]]+\]\s*)?"
    r"(?:=|\+=)\s*[^;]*(?:totalSupply|_totalSupply|supplyBefore|"
    r"totalBefore|denominator)",
    re.IGNORECASE,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            i += 1

        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, i)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for(fn: FunctionSlice, match: re.Match[str] | None) -> int:
    if match is None:
        return fn.body_line
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _branch_blocks(fn: FunctionSlice) -> list[tuple[str, str, re.Match[str]]]:
    blocks: list[tuple[str, str, re.Match[str]]] = []
    for match in _IF_ELSE_BLOCK_RE.finditer(fn.body):
        cond = match.group("cond") or match.group("elif") or "else"
        blocks.append((cond, match.group("body"), match))
    return blocks


def _branch_asymmetric_flag(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if _SYMMETRIC_BRANCH_HINT_RE.search(fn.body):
        return None
    blocks = _branch_blocks(fn)
    if len(blocks) < 2:
        return None

    reward_blocks = [
        (cond, body, match)
        for cond, body, match in blocks
        if _REWARD_SIDE_EFFECT_RE.search(f"{cond}\n{body}")
    ]
    if len(reward_blocks) < 2:
        return None

    flag_blocks = [
        (cond, body, match)
        for cond, body, match in reward_blocks
        if _FLAG_WRITE_RE.search(body)
    ]
    unflagged_reward_blocks = [
        (cond, body, match)
        for cond, body, match in reward_blocks
        if _FLAG_WRITE_RE.search(body) is None
    ]
    if not flag_blocks or not unflagged_reward_blocks:
        return None
    return (
        "mutates reward or idempotency state in only one reward-processing branch",
        unflagged_reward_blocks[0][2],
    )


def _failed_dispatch_pays_relayer(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if _DISPATCH_FAILURE_RE.search(fn.body) is None:
        return None
    if _CATCH_REVERT_RE.search(fn.body):
        return None
    payout = _RELAYER_PAYOUT_RE.search(fn.body)
    if payout is None:
        return None
    if _REQUIRE_SUCCESS_RE.search(fn.body):
        return None
    if _SUCCESS_GATED_PAYOUT_RE.search(fn.body):
        return None
    return (
        "pays relayer reward after a catch path marks dispatch unsuccessful",
        payout,
    )


def _stale_supply_bulk_burn(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not (_BULK_BURN_NAME_RE.search(fn.name) or _BULK_BURN_NAME_RE.search(fn.body)):
        return None
    if not _LOOP_RE.search(fn.body):
        return None
    if _SUPPLY_CHECKPOINT_RE.search(fn.body):
        return None

    snapshot = _SUPPLY_SNAPSHOT_RE.search(fn.body)
    if snapshot is None:
        return None
    var_name = re.escape(snapshot.group("var"))
    reward_calc = re.search(_REWARD_CALC_PREFIX_RE + var_name + r"\b", fn.body, re.IGNORECASE)
    if reward_calc is None:
        return None
    burn = _BURN_OR_SUPPLY_DECREMENT_RE.search(fn.body, reward_calc.end())
    if burn is None:
        return None
    if not (snapshot.start() < reward_calc.start() < burn.start()):
        return None
    return (
        "calculates reward payouts from a pre-burn totalSupply snapshot",
        snapshot,
    )


def _branch_denominator_asymmetry(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if _SUPPLY_CHECKPOINT_RE.search(fn.body):
        return None
    blocks = _branch_blocks(fn)
    if len(blocks) < 2:
        return None
    denominator_blocks = [
        match for _cond, body, match in blocks if _DENOMINATOR_BRANCH_RE.search(body)
    ]
    reward_denominator_blocks = [
        match for _cond, body, match in blocks if _BRANCH_REWARD_DENOMINATOR_RE.search(body)
    ]
    if not denominator_blocks or not reward_denominator_blocks:
        return None
    if len(denominator_blocks) == len(blocks):
        return None
    return (
        "uses a stale supply denominator in one reward branch after sibling supply mutation",
        reward_denominator_blocks[0],
    )


def _first_reason(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    for check in (
        lambda: _branch_asymmetric_flag(fn),
        lambda: _failed_dispatch_pays_relayer(fn),
        lambda: _stale_supply_bulk_burn(fn),
        lambda: _branch_denominator_asymmetry(fn),
    ):
        result = check()
        if result is not None:
            return result
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments_and_strings(source)
    if not _CONTEXT_RE.search(clean_source):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean_source):
        if not _PUBLIC_HEADER_RE.search(fn.header):
            continue
        reason = _first_reason(fn)
        if reason is None:
            continue
        message, anchor = reason
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` {message}. Reward distribution must gate "
                    "failed dispatch payouts and keep reward flags or supply "
                    "denominators symmetric across branches."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
