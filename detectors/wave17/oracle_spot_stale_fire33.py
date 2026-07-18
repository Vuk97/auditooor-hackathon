"""
oracle-spot-stale-fire33

Solidity recall-lift detector for price-sensitive mint, liquidation,
settlement, borrow, redemption, and valuation paths that consume one
instantaneous oracle answer, AMM reserve ratio, or spot price without a
freshness, sequencer, TWAP, confidence, denominator, or outlier guard.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:57361adac683c0c7
- context_pack_hash: 57361adac683c0c7f40a2f345b94c4172fe41a09373a05ca2cf8fae67d1b1dab
- source refs:
  - reports/detector_lift_fire32_20260605/post_priorities_all.md
  - reference/patterns.dsl/oracle-atomic-front-run-manipulation.yaml
  - reference/patterns.dsl/ec-stale-oracle-no-freshness-check.yaml
  - reference/patterns.dsl/ec-spot-price-used-as-oracle.yaml
  - reference/patterns.dsl/oracle-staleness-not-checked.yaml
- attack_class: oracle-price-manipulation
- verification_tier: tier-3-synthetic-taxonomy-anchored

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "oracle-spot-stale-fire33"
DETECTOR_SEVERITY_DEFAULT = "High"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None
    source_kind: Optional[str] = None


@dataclass(frozen=True)
class FunctionSlice:
    name: str
    header: str
    body: str
    line: int
    body_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)

_ORACLE_SURFACE_RE = re.compile(
    r"(?is)\b(?:"
    r"AggregatorV3Interface|latestRoundData|latestAnswer|answer|updatedAt|"
    r"priceFeed|priceOracle|oracle|chainlink|pyth|pythOracle|feed|"
    r"getPrice|getUnderlyingPrice|_getPrice|_fetchPrice|spotPrice|"
    r"getReserves|reserve0|reserve1|slot0|sqrtPriceX96|virtual_price|"
    r"get_dy|getAmountsOut|getAmountsIn"
    r")\b"
)
_CHAINLINK_READ_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*latestRoundData\s*\(|"
    r"\.\s*latestAnswer\s*\(|"
    r"\b(?:latestRoundData|latestAnswer)\s*\("
    r")"
)
_RESERVE_READ_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*getReserves\s*\(|"
    r"\bgetReserves\s*\(|"
    r"\breserve[01]\b|"
    r"\b_reserve[01]\b|"
    r"\.\s*slot0\s*\(|"
    r"\bsqrtPriceX96\b|"
    r"\bvirtual_price\b|"
    r"\bget_dy\s*\(|"
    r"\bgetAmounts(?:Out|In)\s*\("
    r")"
)
_GENERIC_PRICE_READ_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:priceOracle|oracle|feed|aggregator|pyth|pool|pair)\s*\."
    r"(?:getPrice|getUnderlyingPrice|price|getAssetPrice|getValue|"
    r"getRate|read|peek|consult|quote|latestPrice)\s*\(|"
    r"\b(?:getPrice|_getPrice|_fetchPrice|spotPrice|assetPrice|"
    r"oraclePrice|markPrice)\s*\("
    r")"
)
_RATIO_MATH_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:price|value|valuation|worth|collateralValue|debtValue|"
    r"borrowValue|mintAmount|settlementAmount)\w*\s*=\s*[^;]{0,240}"
    r"(?:reserve[01]|_reserve[01]|sqrtPriceX96|virtual_price)|"
    r"(?:reserve[01]|_reserve[01])\s*[*\/]\s*(?:reserve[01]|_reserve[01])|"
    r"(?:amount|shares|collateral|debt|supply|assets)\w*\s*[*\/]\s*"
    r"(?:reserve[01]|_reserve[01]|price|answer)"
    r")"
)
_PRICE_SENSITIVE_RE = re.compile(
    r"(?is)\b(?:"
    r"mint\w*|issue\w*|borrow\w*|repay\w*|liquidat\w*|settle\w*|"
    r"redeem\w*|withdraw\w*|deposit\w*|collateral\w*|valuation\w*|"
    r"valueOf\w*|assetValue\w*|accountLiquidity\w*|liquidity\w*|"
    r"health\w*|solvency\w*|debt\w*|borrowLimit\w*|maxBorrow\w*|"
    r"ltv\w*|loanToValue\w*|margin\w*|markPrice\w*|fillOrder\w*|"
    r"swap\w*|quote\w*|payout\w*|claim\w*"
    r")\b"
)
_SAFE_FRESHNESS_RE = re.compile(
    r"(?is)(?:"
    r"\bupdatedAt\b|"
    r"\bansweredInRound\b|"
    r"\broundId\b|"
    r"\bheartbeat\b|"
    r"\bmax(?:imum)?(?:Staleness|Delay|Age|OracleDelay|FeedDelay)\b|"
    r"\bSTALE(?:NESS)?\b|"
    r"\bstale(?:ness)?\b|"
    r"\bfresh(?:ness)?\b|"
    r"\bblock\s*\.\s*timestamp\s*-\s*\w+|"
    r"\b\w+\s*\+\s*\w+\s*[<>=!]=?\s*block\s*\.\s*timestamp"
    r")"
)
_SAFE_TWAP_OR_DELAY_RE = re.compile(
    r"(?is)(?:"
    r"\btwap\b|\bTWAP\b|\btimeWeighted\b|\bweightedAverage\b|"
    r"\bmovingAverage\b|\bcumulative(?:Price)?\b|\bobserve\s*\(|"
    r"\bconsult\s*\(|\bwindow\b|\bmin(?:imum)?Blocks\b|"
    r"\bmin(?:imum)?Delay\b|\bcooldown\b"
    r")"
)
_SAFE_SEQUENCER_RE = re.compile(
    r"(?is)(?:"
    r"\bsequencer\b|\bSequencer\b|\buptimeFeed\b|\bgracePeriod\b|"
    r"\bGRACE_PERIOD\b|\bsequencerGrace\b"
    r")"
)
_SAFE_CONFIDENCE_OR_OUTLIER_RE = re.compile(
    r"(?is)(?:"
    r"\bconfidence\b|\bconf\b|\bmaxConfidence\b|\bconfidenceInterval\b|"
    r"\bdeviation\b|\bmaxDeviation\b|\boutlier\b|\boutlierGuard\b|"
    r"\bcircuitBreaker\b|\bminAnswer\b|\bmaxAnswer\b|"
    r"\blowerBound\b|\bupperBound\b|\bpriceBand\b|\bclamp(?:ed)?\b"
    r")"
)
_DENOM_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\brequire\s*\([^;{}]*(?:reserve[01]|_reserve[01]|denom|denominator)"
    r"[^;{}]*(?:>|!=)\s*0|"
    r"\bif\s*\([^;{}]*(?:reserve[01]|_reserve[01]|denom|denominator)"
    r"[^;{}]*(?:==|<=)\s*0\s*\)\s*(?:revert|return)"
    r")"
)
_SAFE_HELPER_RE = re.compile(
    r"(?is)\b(?:"
    r"ORACLE_SPOT_STALE_FIRE33_SAFE|freshPrice|_freshPrice|"
    r"validatedPrice|_validatedPrice|checkedPrice|_checkedPrice|"
    r"twapPrice|_twapPrice|boundedPrice|_boundedPrice|"
    r"safeOraclePrice|_safeOraclePrice"
    r")\s*\("
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
            pos = max(i, j)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        line = source.count("\n", 0, match.start()) + 1
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line, body_line=body_line))
        pos = end_pos
    return out


def _context(fn: FunctionSlice) -> str:
    return f"{fn.name}\n{fn.header}\n{fn.body}"


def _line_for(fn: FunctionSlice, match: re.Match[str] | None) -> int:
    if match is None:
        return fn.line
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _price_source_match(text: str) -> tuple[str, re.Match[str] | None]:
    chainlink = _CHAINLINK_READ_RE.search(text)
    reserve = _RESERVE_READ_RE.search(text)
    generic = _GENERIC_PRICE_READ_RE.search(text)
    ratio = _RATIO_MATH_RE.search(text)

    if chainlink is not None:
        return "single latest oracle answer", chainlink
    if reserve is not None and (ratio is not None or _PRICE_SENSITIVE_RE.search(text)):
        return "single AMM or pool spot price", reserve
    if generic is not None:
        return "single generic oracle spot price", generic
    return "", None


def _has_any_guard(text: str, *, reserve_source: bool) -> bool:
    if _SAFE_HELPER_RE.search(text):
        return True
    if _SAFE_FRESHNESS_RE.search(text):
        return True
    if _SAFE_TWAP_OR_DELAY_RE.search(text):
        return True
    if _SAFE_SEQUENCER_RE.search(text):
        return True
    if _SAFE_CONFIDENCE_OR_OUTLIER_RE.search(text):
        return True
    if reserve_source and _DENOM_GUARD_RE.search(text):
        return True
    return False


def _is_candidate(fn: FunctionSlice) -> tuple[str, re.Match[str] | None]:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return "", None

    text = _context(fn)
    if not _ORACLE_SURFACE_RE.search(text):
        return "", None
    if not _PRICE_SENSITIVE_RE.search(text):
        return "", None

    source_kind, match = _price_source_match(text)
    if not source_kind or match is None:
        return "", None

    reserve_source = "AMM" in source_kind or "pool" in source_kind
    if _has_any_guard(text, reserve_source=reserve_source):
        return "", None

    return source_kind, match


def _finding(file_path: str, fn: FunctionSlice, source_kind: str, match: re.Match[str]) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=_line_for(fn, match),
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        source_kind=source_kind,
        message=(
            f"Price-sensitive path consumes a {source_kind} before mint, "
            "liquidation, settlement, borrow, redemption, or valuation math "
            "without a heartbeat or updatedAt freshness check, sequencer "
            "grace window, TWAP window, confidence bound, denominator guard, "
            "or outlier guard. NOT_SUBMIT_READY: detector fixture smoke "
            "evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        source_kind, match = _is_candidate(fn)
        if not source_kind or match is None:
            continue
        findings.append(_finding(file_path, fn, source_kind, match))
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
]
