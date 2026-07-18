"""
rewards-period-cache-skew-fire25

Solidity same-class recall detector for rewards-distribution-skew misses where
a period, epoch, or reward cache transition writes only the current cache slot
or mutates reward weight and supply state before settling accrued rewards.

Confirmed sources:
- c4-ramses-period-cache-skip-inflated-rewards
- period-cache-skipped-interval-inflation
- Fire23 and Fire24 rewards-distribution-skew regex detector family

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-period-cache-skew-fire25"
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

_REWARD_PERIOD_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|emission\w*|incentive\w*|claimable\w*|"
    r"pending\w*|accrued\w*|period\w*|epoch\w*|week\w*|"
    r"checkpoint\w*|cache\w*|cumulative\w*|secondsPerLiquidity|"
    r"accReward\w*|rewardPer\w*|totalSupply|balance\w*|weight\w*)\b",
    re.IGNORECASE,
)
_PERIOD_CACHE_WRITE_RE = re.compile(
    r"\b(?:periodCumulatives?|cumulativesInside|periodCache|epochCache|"
    r"rewardPeriodCache|periodRewardCache|secondsPerLiquidityCumulative|"
    r"periodRewardPerWeight|periodRewardPerToken|periodSupply|"
    r"periodTotalSupply|epochSupply)\s*\[[^\]]*(?:current|next|period|"
    r"epoch|week)[^\]]*\]\s*=|"
    r"\b(?:lastUpdatePeriod|lastPeriod|lastEpoch|cachedPeriod|cachedEpoch|"
    r"currentPeriod|currentEpoch)\s*=\s*(?:current|nextPeriod|nextEpoch|"
    r"period|epoch|week)",
    re.IGNORECASE | re.DOTALL,
)
_GAP_FILL_OR_CONTIGUITY_RE = re.compile(
    r"\b(?:_?fillGap|_?backfill|fillForward|_?materializeEpoch|"
    r"_?materializePeriod|_?settlePeriod|_?checkpointPeriod|"
    r"_?checkpointEpoch|_?advancePeriodSafely)\s*\(|"
    r"\b(?:for|while)\s*\([^)]*(?:period|epoch|week)[^)]*(?:<=|<)"
    r"[^)]*(?:current|next|toPeriod|toEpoch|endPeriod|endEpoch)|"
    r"\brequire\s*\([^;{}]*(?:current|nextPeriod|nextEpoch|period|epoch)"
    r"\s*==\s*(?:lastUpdatePeriod|lastPeriod|lastEpoch|cachedPeriod|"
    r"cachedEpoch|currentPeriod|currentEpoch)\s*\+\s*1",
    re.IGNORECASE | re.DOTALL,
)
_SETTLEMENT_RE = re.compile(
    r"\b(?:_?settleRewards?|_?settleReward|_?accrueRewards?|"
    r"_?accrueReward|_?checkpointRewards?|_?checkpointReward|"
    r"_?checkpointAccount|_?checkpointUser|_?checkpointGlobal|"
    r"_?updateRewards?|_?updateReward|_?updateRewardPerToken|"
    r"_?syncRewards?|_?syncReward|_?updatePool|_?settlePool)\s*\(|"
    r"\b(?:rewardPerTokenStored|globalRewardPerWeight|accRewardPerShare|"
    r"accRewardPerWeight|rewardIndex|globalRewardIndex)\s*(?:\[[^\]]+\]\s*)?"
    r"(?:=|\+=)",
    re.IGNORECASE,
)
_WEIGHT_OR_SUPPLY_MUTATION_RE = re.compile(
    r"\b(?:periodRewardWeight|rewardWeight|rewardWeights|poolWeight|"
    r"poolWeights|totalWeight|allocPoint|allocationPoint|periodSupply|"
    r"periodTotalSupply|epochSupply|totalSupply|_totalSupply|balances|"
    r"balanceOf|staked|stakeOf|stakes|totalStaked|totalStake|shares|"
    r"userShares)\b\s*(?:\[[^\]]+\]\s*)*(?:=|\+=|-=|\+\+|--)|"
    r"\b(?:_?mint|_?burn|_?stake|_?unstake|_?deposit|_?withdraw|"
    r"_?setPoolWeight|_?setRewardWeight|_?setWeight|_?setAllocPoint)\s*\(",
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
    return source[open_brace + 1:close_brace], close_brace + 1


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

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for(fn: FunctionSlice, match: re.Match[str] | None) -> int:
    if match is None:
        return fn.body_line
    return fn.body_line + fn.body.count("\n", 0, max(0, match.start()))


def _period_cache_skips_gap_fill(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    cache_write = _PERIOD_CACHE_WRITE_RE.search(fn.body)
    if cache_write is None:
        return None
    if _GAP_FILL_OR_CONTIGUITY_RE.search(fn.body):
        return None
    if not re.search(r"\b(?:lastUpdatePeriod|lastPeriod|lastEpoch|cachedPeriod|cachedEpoch)\b", fn.body):
        return None
    return (
        "writes only the current reward period cache without filling skipped periods",
        cache_write,
    )


def _period_mutation_before_settlement(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    cache_write = _PERIOD_CACHE_WRITE_RE.search(fn.body)
    if cache_write is None:
        return None

    mutation = _WEIGHT_OR_SUPPLY_MUTATION_RE.search(fn.body)
    if mutation is None:
        return None

    settlement = _SETTLEMENT_RE.search(fn.body)
    if settlement is not None and settlement.start() < mutation.start():
        return None

    return (
        "mutates reward weight or supply before settling accrued reward state for the period cache transition",
        mutation,
    )


def _first_reason(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    for check in (
        lambda: _period_mutation_before_settlement(fn),
        lambda: _period_cache_skips_gap_fill(fn),
    ):
        result = check()
        if result is not None:
            return result
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _REWARD_PERIOD_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
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
                    f"`{fn.name}` has reward period cache skew: {message}. "
                    "Period cache updates must backfill skipped periods and "
                    "must settle or checkpoint user and global rewards before "
                    "mutating weight, balance, or total supply."
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
