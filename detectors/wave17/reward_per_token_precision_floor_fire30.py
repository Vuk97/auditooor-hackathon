"""
reward-per-token-precision-floor-fire30

Fire30 Solidity lift for reward, fee, and share math that floors an
intermediate value before applying the load-bearing precision, fee-rate, or
share multiplier.

Source refs:
- reports/detector_lift_fire29_20260605/post_priorities_solidity.md
- reference/patterns.dsl/rewardloss-in-staking-contracts.yaml
- reference/patterns.dsl/dh-laura-reward-on-balanceOf-inflatable.yaml
- reference/patterns.dsl.zellic_k2_mined/rewards-lost-when-total-supply-drops-to-zero.yaml

Candidate evidence only. A hit is NOT_SUBMIT_READY and must not be cited as
proof without source existence, a real in-scope entrypoint, negative control,
and R40/R76/R80 evidence honesty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "reward-per-token-precision-floor-fire30"
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
    function_line: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public|internal)\b")
_PURE_VIEW_RE = re.compile(r"(?i)\b(?:pure|view)\b")
_ENTRY_RE = re.compile(
    r"(?i)^(?:accrue|borrow|charge|checkpoint|claim|collect|convert|"
    r"deposit|distribute|harvest|mint|notify|preview|redeem|repay|"
    r"settle|sync|update|withdraw)"
)
_ACCOUNTING_CONTEXT_RE = re.compile(
    r"(?is)\b(?:accRewardPerShare|assets?|balance|borrow|bps|BPS|debt|"
    r"emission|fee|fees|index|pending|perShare|perToken|precision|"
    r"premium|principal|rate|reward|rewards|shares?|stake|staked|"
    r"totalAssets|totalShares|totalStaked|totalSupply)\b"
)

_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?P<op>\+=|=)\s*(?P<expr>[^;{}]{1,420})\s*;"
)

_SAFE_HELPER_RE = re.compile(
    r"(?is)\b(?:mulDiv|fullMulDiv|FullMath\s*\.\s*mulDiv|"
    r"Math\s*\.\s*mulDiv|FixedPointMathLib\s*\.\s*mulDiv|"
    r"mulWad|mulRay|mulDivUp|mulDivCeil|mulDivRoundingUp|"
    r"ceilDiv|divUp|divCeil|Rounding\s*\.\s*Up|roundUp)\b"
)
_ROUND_UP_FORMULA_RE = re.compile(
    r"(?is)(?:\+\s*(?:BPS|BASIS_POINTS|DENOMINATOR|FEE_DENOMINATOR|"
    r"ACC_PRECISION|PRECISION|SCALE|WAD|RAY|denominator|totalShares|"
    r"totalSupply|totalStaked)\s*-\s*1|-\s*1\s*\)\s*/)"
)
_REMAINDER_RE = re.compile(
    r"(?is)\b(?:carry|dust|feeRemainder|indexRemainder|leftover|"
    r"remainder|residual|rewardRemainder|undistributed|unallocated|"
    r"queuedReward)\b"
)
_SCALE_FIRST_RE = re.compile(
    r"(?is)\*\s*(?:ACC_PRECISION|PRECISION|SCALE|WAD|RAY|"
    r"1e18|1e12|1000000000000000000|1000000000000)\s*/"
)

_REWARD_RE = re.compile(
    r"(?is)(?:accRewardPerShare|accPerShare|emission|index|perShare|"
    r"perToken|reward|rewards|rewardDelta|rewardIndex|rewardPerShare|"
    r"rewardPerToken)"
)
_FEE_RE = re.compile(
    r"(?is)\b(?:basis|bps|BPS|fee|fees|FEE|premium|principal|rate|"
    r"protocolFee|treasury|borrow|repay|DENOMINATOR)\b"
)
_SHARE_RE = re.compile(
    r"(?is)\b(?:asset|assets|balance|convert|mint|redeem|share|shares|"
    r"totalAssets|totalShares|totalSupply|withdraw)\b"
)
_SUPPLY_DENOM_RE = re.compile(
    r"(?is)\b(?:totalStaked|totalStake|totalSupply|_totalSupply|"
    r"stakingSupply|stakedSupply|totalShares|shareSupply|sharesSupply|"
    r"supply|shares|stake)\b"
)
_ASSET_DENOM_RE = re.compile(
    r"(?is)\b(?:totalAssets|assets|assetBalance|poolAssets|balance)\b"
)
_FEE_DENOM_RE = re.compile(
    r"(?is)\b(?:BPS|BASIS_POINTS|DENOMINATOR|FEE_DENOMINATOR|"
    r"YEAR_SECONDS|SECONDS_PER_YEAR|duration|period|rewardDuration|"
    r"rewardsDuration)\b"
)
_PRECISION_OR_INDEX_MULT_RE = re.compile(
    r"(?is)\b(?:ACC_PRECISION|PRECISION|SCALE|WAD|RAY|1e18|1e12|"
    r"1000000000000000000|1000000000000|accRewardPerShare|accPerShare|"
    r"rewardIndex|rewardPerShare|rewardPerToken|index)\b"
)
_FEE_RATE_MULT_RE = re.compile(
    r"(?is)\b(?:basis|bps|BPS|feeBps|feeRate|rate|premiumBps|"
    r"protocolFeeBps|exitFeeBps|borrowFeeBps)\b"
)
_SHARE_MULT_RE = re.compile(
    r"(?is)\b(?:shares?|shareAmount|totalShares|totalSupply|_totalSupply|"
    r"supply|ACC_PRECISION|PRECISION|SCALE|WAD|RAY)\b"
)
_DUST_IMPACT_RE = re.compile(
    r"(?is)(?:consumed|lastBalance|paid|protocolFees|rewardPerToken|"
    r"rewardIndex|rewardPerShare|totalAssets|totalSupply|treasury|"
    r"withdraw|borrowed|debt|shares|transfer)"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


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
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
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

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1
        if depth != 0:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, function_line=line))
        pos = k
    return out


def _line_for(function_line: int, text: str, match: re.Match[str]) -> int:
    return function_line + text.count("\n", 0, match.start())


def _window(text: str, start: int, end: int) -> str:
    return text[max(0, start - 300):min(len(text), end + 900)]


def _is_accounting_function(fn: FunctionSlice, text: str) -> bool:
    if not _VISIBILITY_RE.search(fn.header):
        return False
    if _PURE_VIEW_RE.search(fn.header):
        return False
    return bool(_ENTRY_RE.search(fn.name) or _ACCOUNTING_CONTEXT_RE.search(text))


def _safe_near(text: str, start: int, end: int) -> bool:
    window = _window(text, start, end)
    return bool(
        _SAFE_HELPER_RE.search(window)
        or _ROUND_UP_FORMULA_RE.search(window)
        or _REMAINDER_RE.search(window)
    )


def _find_div_before_mul(expr: str) -> tuple[str, str, str] | None:
    slash = expr.find("/")
    star = expr.find("*", slash + 1)
    if slash < 0 or star < 0:
        return None
    before = expr[:slash]
    denominator = expr[slash + 1:star]
    multiplier = expr[star + 1:]
    return before, denominator, multiplier


def _find_plain_floor(expr: str) -> tuple[str, str] | None:
    if "*" in expr:
        return None
    slash = expr.find("/")
    if slash < 0:
        return None
    return expr[:slash], expr[slash + 1:]


def _branch_for_div_before_mul(target: str, expr: str) -> str | None:
    parts = _find_div_before_mul(expr)
    if parts is None:
        return None
    before, denominator, multiplier = parts
    context = f"{target} {expr}"
    if (
        _REWARD_RE.search(context)
        and _SUPPLY_DENOM_RE.search(denominator)
        and _PRECISION_OR_INDEX_MULT_RE.search(multiplier)
    ):
        return "reward per token precision floor"
    if (
        _FEE_RE.search(context)
        and _FEE_DENOM_RE.search(denominator)
        and _FEE_RATE_MULT_RE.search(multiplier)
    ):
        return "fee precision floor"
    if (
        _SHARE_RE.search(context)
        and (_ASSET_DENOM_RE.search(denominator) or _SUPPLY_DENOM_RE.search(denominator))
        and _SHARE_MULT_RE.search(multiplier)
    ):
        return "share conversion precision floor"
    if (
        _SHARE_RE.search(context)
        and (_ASSET_DENOM_RE.search(before) or _SUPPLY_DENOM_RE.search(before))
        and _SHARE_MULT_RE.search(multiplier)
    ):
        return "share conversion precision floor"
    return None


def _zero_guard_before_use(var_name: str, tail_before_use: str) -> bool:
    quoted = re.escape(var_name)
    return bool(
        re.search(
            rf"(?is)if\s*\([^;{{}}]*\b{quoted}\b[^;{{}}]*(?:==\s*0|<\s*1)"
            rf"[^;{{}}]*\)\s*(?:return|revert|throw)",
            tail_before_use,
        )
        or re.search(
            rf"(?is)require\s*\([^;{{}}]*\b{quoted}\b[^;{{}}]*(?:>\s*0|>=\s*1|!=\s*0)",
            tail_before_use,
        )
    )


def _branch_for_temp_floor(var_name: str, expr: str, tail: str) -> str | None:
    parts = _find_plain_floor(expr)
    if parts is None:
        return None
    before, denominator = parts
    use = re.search(
        rf"(?is)(?:\b{re.escape(var_name)}\b\s*\*[^;{{}}]{{0,180}}|"
        rf"[^;{{}}]{{0,180}}\*\s*\b{re.escape(var_name)}\b)",
        tail,
    )
    if use is None:
        return None
    if _zero_guard_before_use(var_name, tail[:use.start()]):
        return None
    use_window = tail[use.start():use.end()]
    context = f"{var_name} {expr} {use_window}"
    if (
        _REWARD_RE.search(context)
        and _SUPPLY_DENOM_RE.search(denominator)
        and _PRECISION_OR_INDEX_MULT_RE.search(use_window)
    ):
        return "reward per token precision floor"
    if (
        _FEE_RE.search(context)
        and _FEE_DENOM_RE.search(denominator)
        and _FEE_RATE_MULT_RE.search(use_window)
    ):
        return "fee precision floor"
    if (
        _SHARE_RE.search(context)
        and (_ASSET_DENOM_RE.search(denominator) or _SUPPLY_DENOM_RE.search(denominator))
        and _SHARE_MULT_RE.search(use_window)
    ):
        return "share conversion precision floor"
    return None


def _impactful_tail(text: str, start: int) -> bool:
    return bool(_DUST_IMPACT_RE.search(text[start:start + 1400]))


def _match_function(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    if not _is_accounting_function(fn, text):
        return None

    for match in _ASSIGN_RE.finditer(text):
        if _safe_near(text, match.start(), match.end()):
            continue
        var_name = match.group("var")
        expr = match.group("expr")

        branch = _branch_for_div_before_mul(var_name, expr)
        if branch is not None and _impactful_tail(text, match.end()):
            return match, branch

        branch = _branch_for_temp_floor(var_name, expr, text[match.end():])
        if branch is not None and _impactful_tail(text, match.end()):
            return match, branch
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        result = _match_function(fn, text)
        if result is None:
            continue
        match, branch = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn.function_line, text, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` has a {branch}: denominator division "
                    "floors an intermediate value before the precision, "
                    "fee-rate, or share multiplier is applied. Carry the "
                    "remainder, scale before dividing, or use mulDiv."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
