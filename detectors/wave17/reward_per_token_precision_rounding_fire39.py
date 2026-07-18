"""
reward-per-token-precision-rounding-fire39

Solidity detector for rounding-direction-attack candidates in reward and
liquidation-fee accounting:

1. reward-per-token or accumulated-per-share indexes that add
   reward / totalSupply-style quotients without scaling before division,
   or that scale only after the lossy division;
2. liquidation protocol fee shares converted with floor-style ray division
   before a downstream transfer expects the same conversion rounded up.

verification_tier: tier-3-synthetic-taxonomy-anchored
attack_class: rounding-direction-attack
context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
MCP receipt: .auditooor/memory_context_receipt.json
NOT_SUBMIT_READY
R40/R76/R80 caveat: detector hits are source-review candidates only, not
proof. Promote only after source-existence review, real protocol path PoC,
negative control, and non-vacuous evidence.

Source refs:
- reports/detector_lift_fire38_20260605/post_priorities_solidity.md
- detectors/wave17/integer_clamp_underflow_fire38.py
- detectors/wave17/rewards_branch_asymmetry_fire38.py
- reference/patterns.dsl/ec-reward-per-token-precision-loss.yaml
- reference/patterns.dsl/fx-aave-liquidation-fee-rounding-direction.yaml
- reference/patterns.dsl/flashloan-no-fee-charged.yaml
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "reward-per-token-precision-rounding-fire39"
DETECTOR_SEVERITY_DEFAULT = "Medium"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
ATTACK_CLASS = "rounding-direction-attack"


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None
    branch: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    function_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBLE_RE = re.compile(r"\b(?:external|public|internal)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b")

_REWARD_SURFACE_RE = re.compile(
    r"(?is)\b(?:reward\w*|rewards\w*|rewardPerToken\w*|rewardPerShare\w*|"
    r"accRewardPerShare|accumulatedRewardPerShare|accPerShare|"
    r"rewardIndex\w*|globalRewardIndex\w*|emission\w*|emissions\w*|"
    r"incentive\w*|notifyReward\w*|distribute\w*|drip\w*|harvest\w*|"
    r"claimable\w*|pendingReward\w*)\b"
)
_REWARD_NUMERATOR_RE = re.compile(
    r"(?is)\b(?:reward|rewards|rewardAmount|rewardDelta|newReward|"
    r"periodReward|emission|emissions|drip|bonus|incentive|amount)\w*\b"
)
_SUPPLY_DENOM_RE = re.compile(
    r"(?is)\b(?:totalStaked|totalStake|totalSupply|_totalSupply|"
    r"stakedSupply|stakingSupply|shareSupply|sharesSupply|poolSupply|"
    r"totalShares|supply|shares|stake)\b"
)
_INDEX_TARGET_RE = (
    r"(?:rewardPerTokenStored|rewardPerToken|rewardPerShare|"
    r"accRewardPerShare|accumulatedRewardPerShare|accPerShare|"
    r"rewardIndex|globalRewardIndex|emissionIndex|cumulativeRewardPerToken|"
    r"cumulativeRewardPerShare)"
)
_INDEX_WRITE_RE = re.compile(
    rf"(?is)\b(?P<target>{_INDEX_TARGET_RE})\s*(?:\[[^\]]+\]\s*)?"
    rf"(?:\+=|=\s*(?P=target)\s*\+|=)\s*(?P<expr>[^;{{}}]{{1,360}})\s*;"
)
_TEMP_REWARD_INCREMENT_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:Reward|Rewards|PerToken|"
    r"PerShare|Index|Increment|Delta|Accrued|Emission|Share|Rate)"
    r"|increment|delta|rewardShare|rewardUnit)\s*=\s*"
    r"(?P<expr>[^;{}]{1,360})\s*;"
)

_SCALE_RE = re.compile(
    r"(?is)\b(?:ACC_PRECISION|PRECISION|REWARD_PRECISION|INDEX_PRECISION|"
    r"SCALE|SCALAR|WAD|RAY|BASE|1e18|1e12|10\s*\*\*\s*(?:18|12)|"
    r"1000000000000000000|1000000000000|1_000_000_000_000_000_000|"
    r"1_000_000_000_000)\b"
)
_SAFE_MATH_RE = re.compile(
    r"(?is)\b(?:mulDiv|Math\s*\.\s*mulDiv|FullMath\s*\.\s*mulDiv|"
    r"FixedPointMathLib\s*\.\s*mulDiv|PRBMath|mulWad|mulRay|rayMul|"
    r"wadMul|divWadUp|mulWadUp|mulDivUp|mulDivCeil|ceilDiv|"
    r"Rounding\s*\.\s*(?:Up|Ceil|Floor|Down))\b"
)
_ROUND_UP_RE = re.compile(
    r"(?is)\b(?:rayDivCeil|rayDivUp|toSharesUp|toScaledUp|mulDivUp|"
    r"mulDivCeil|mulDivRoundingUp|ceilDiv|divUp|roundUp|"
    r"Rounding\s*\.\s*Up|Math\s*\.\s*mulDiv\s*\([^;{}]{1,340}"
    r"Rounding\s*\.\s*Up)\b"
)
_REMAINDER_RE = re.compile(
    r"(?is)\b(?:dust|remainder|leftover|carry|undistributed|unallocated|"
    r"residual|queuedReward|rewardRemainder|emissionRemainder|"
    r"indexRemainder)\b"
)
_ZERO_INCREMENT_GUARD_RE = re.compile(
    r"(?is)(?:require\s*\([^;{}]*(?:increment|delta|rewardShare|"
    r"rewardUnit|rewardPerToken|accRewardPerShare|rewardIndex)[^;{}]*"
    r"(?:>\s*0|!=\s*0|>=\s*1)|"
    r"if\s*\([^;{}]*(?:increment|delta|rewardShare|rewardUnit|"
    r"rewardPerToken|accRewardPerShare|rewardIndex)[^;{}]*"
    r"(?:==\s*0|<\s*1)[^;{}]*\)\s*(?:\{|return|revert|throw))"
)

_LIQUIDATION_CONTEXT_RE = re.compile(
    r"(?is)\b(?:liquidat|debtToCover|collateralToSeize|"
    r"liquidationProtocolFee|liquidationFee|protocolFee|"
    r"feeAmount|liquidityIndex|scaledBalance|aToken)\b"
)
_FEE_SHARE_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:Scaled|Shares|Share|FeeShares|"
    r"ProtocolFee|ProtocolShare)|scaledFee|feeShares|protocolFeeShares)"
    r"\s*=\s*(?P<expr>[^;{}]{1,420})\s*;"
)
_FLOOR_CONVERSION_RE = re.compile(
    r"(?is)\b(?:rayDivFloor|rayDiv\s*\(|toSharesDown|toScaledDown|"
    r"mulDivDown|mulWadDown|Rounding\s*\.\s*Down|Math\s*\.\s*mulDiv)\b"
)
_FEE_CONVERSION_DOMAIN_RE = re.compile(
    r"(?is)\b(?:fee|fees|protocolFee|liquidationProtocolFee|"
    r"liquidationFee|feeAmount|liquidityIndex|index|scaled|shares?)\b"
)
_FEE_SHARE_SINK_RE = re.compile(
    r"(?is)\b(?:transferOnLiquidation|transferScaled|scaledTransfer|"
    r"safeTransfer|transfer|protocolFees|treasury|feeCollector|"
    r"accruedFees|scaledBalance|scaledProtocolFee)\b"
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
    index = open_pos + 1
    while index < len(source) and depth > 0:
        if source[index] == open_char:
            depth += 1
        elif source[index] == close_char:
            depth -= 1
        index += 1
    return index - 1 if depth == 0 else -1


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
        scan_pos = close_paren + 1
        while scan_pos < len(source):
            if source[scan_pos] == ";":
                break
            if source[scan_pos] == "{":
                body_start = scan_pos
                break
            scan_pos += 1
        if body_start < 0:
            pos = max(scan_pos, close_paren + 1)
            continue

        body_end = _find_matching_delimiter(source, body_start, "{", "}")
        if body_end < 0:
            pos = body_start + 1
            continue

        out.append(
            FunctionSlice(
                name=name,
                header=source[match.start():body_start],
                body=source[body_start + 1:body_end],
                function_line=source.count("\n", 0, match.start()) + 1,
            )
        )
        pos = body_end + 1
    return out


def _line_for(function_line: int, text: str, match: re.Match[str]) -> int:
    return function_line + text.count("\n", 0, match.start())


def _window(text: str, start: int, end: int, before: int = 520, after: int = 900) -> str:
    return text[max(0, start - before): min(len(text), end + after)]


def _is_mutating_visible(fn: FunctionSlice) -> bool:
    return bool(_VISIBLE_RE.search(fn.header)) and not _VIEW_OR_PURE_RE.search(fn.header)


def _scale_before_first_division(expr: str) -> bool:
    slash = expr.find("/")
    if slash < 0:
        return False
    return bool(_SCALE_RE.search(expr[:slash]))


def _scale_after_first_division(expr: str) -> bool:
    slash = expr.find("/")
    if slash < 0:
        return False
    return bool(_SCALE_RE.search(expr[slash + 1:]))


def _expr_is_unscaled_reward_quotient(expr: str) -> bool:
    if "/" not in expr:
        return False
    if _SAFE_MATH_RE.search(expr) or _scale_before_first_division(expr):
        return False
    slash = expr.find("/")
    numerator = expr[:slash]
    denominator = expr[slash + 1:]
    if not (_REWARD_NUMERATOR_RE.search(numerator) and _SUPPLY_DENOM_RE.search(denominator)):
        return False
    return True


def _has_remainder_or_zero_guard(text: str, start: int, end: int) -> bool:
    window = _window(text, start, end, before=420, after=1100)
    return bool(_REMAINDER_RE.search(window) or _ZERO_INCREMENT_GUARD_RE.search(window))


def _reward_match_safe(text: str, match: re.Match[str]) -> bool:
    expr = match.group("expr")
    if _SAFE_MATH_RE.search(expr) or _scale_before_first_division(expr):
        return True
    if _has_remainder_or_zero_guard(text, match.start(), match.end()):
        return True
    return False


def _tail_updates_reward_index(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1200]
    escaped = re.escape(var_name)
    return bool(
        re.search(rf"(?is)\b{_INDEX_TARGET_RE}\b\s*(?:\[[^\]]+\]\s*)?\+=\s*\b{escaped}\b", tail)
        or re.search(
            rf"(?is)\b{_INDEX_TARGET_RE}\b\s*=\s*\b{_INDEX_TARGET_RE}\b\s*\+\s*\b{escaped}\b",
            tail,
        )
    )


def _direct_reward_index_match(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    if not (_is_mutating_visible(fn) and _REWARD_SURFACE_RE.search(text)):
        return None
    for match in _INDEX_WRITE_RE.finditer(text):
        if _reward_match_safe(text, match):
            continue
        expr = match.group("expr")
        if not _expr_is_unscaled_reward_quotient(expr):
            continue
        if _scale_after_first_division(expr):
            return match, "scale-after-division reward index"
        return match, "unscaled reward index"
    return None


def _temp_reward_index_match(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    if not (_is_mutating_visible(fn) and _REWARD_SURFACE_RE.search(text)):
        return None
    for match in _TEMP_REWARD_INCREMENT_RE.finditer(text):
        if _reward_match_safe(text, match):
            continue
        expr = match.group("expr")
        var_name = match.group("var")
        if not _expr_is_unscaled_reward_quotient(expr):
            continue
        if not _tail_updates_reward_index(text, var_name, match.end()):
            continue
        if _scale_after_first_division(expr):
            return match, "temporary scale-after-division reward increment"
        return match, "temporary unscaled reward increment"
    return None


def _liquidation_floor_match(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    if not (_is_mutating_visible(fn) and _LIQUIDATION_CONTEXT_RE.search(text)):
        return None
    for match in _FEE_SHARE_ASSIGN_RE.finditer(text):
        expr = match.group("expr")
        if _ROUND_UP_RE.search(_window(text, match.start(), match.end(), before=500, after=700)):
            continue
        if not (_FLOOR_CONVERSION_RE.search(expr) and _FEE_CONVERSION_DOMAIN_RE.search(expr)):
            continue
        tail = text[match.end():match.end() + 1200]
        var_name = match.group("var")
        if not (_FEE_SHARE_SINK_RE.search(tail) and re.search(rf"\b{re.escape(var_name)}\b", tail)):
            continue
        return match, "liquidation protocol fee floor conversion"
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        candidates = (
            _direct_reward_index_match(fn, text),
            _temp_reward_index_match(fn, text),
            _liquidation_floor_match(fn, text),
        )
        result = next((candidate for candidate in candidates if candidate is not None), None)
        if result is None:
            continue

        match, branch = result
        if "liquidation" in branch:
            message = (
                f"`{fn.name}` converts liquidation protocol fee shares with "
                "floor-style rounding before a downstream transfer or fee "
                "sink uses that value. Match the downstream share conversion "
                "rounding direction with ceil math or an explicit nonzero "
                "guard. (class: rounding-direction-attack, posture: "
                "NOT_SUBMIT_READY)"
            )
        else:
            article = "an" if branch[:1].lower() in {"a", "e", "i", "o", "u"} else "a"
            message = (
                f"`{fn.name}` updates reward-per-token accounting with {article} "
                f"{branch} quotient. Scale before dividing, use full-precision "
                "mulDiv, or carry the remainder so small rewards cannot be "
                "rounded away. (class: rounding-direction-attack, posture: "
                "NOT_SUBMIT_READY)"
            )
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn.function_line, text, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                branch=branch,
                message=message,
            )
        )

    return findings


__all__ = [
    "ATTACK_CLASS",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "SUBMISSION_POSTURE",
    "VERIFICATION_TIER",
    "scan",
]
