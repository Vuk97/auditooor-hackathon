"""
fund-loss-stale-value-input-fire26

Source-backed Fire26 detector for stale value inputs in arithmetic accounting.

Primary source-backed branch:
- reference/patterns.dsl/interest-rate-update-stale-utilization.yaml
- patterns/fixtures/interest-rate-update-stale-utilization_vuln.sol
- patterns/fixtures/interest-rate-update-stale-utilization_clean.sol

Primary Glider blockhash candidate was not used as the source-backed close
because its migrated fixture only proves a bare function-name match. This
detector only flags blockhash use when the value feeds price, rate, payout, or
accounting arithmetic and the function lacks a current 256-block or zero-hash
validation.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path as _Path
from typing import Iterable

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract  # noqa: E402

try:  # Slither is optional for the regex runner import path.
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except ImportError:  # pragma: no cover - exercised only on hosts without slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        MEDIUM = "Medium"
        LOW = "Low"


DETECTOR_NAME = "fund-loss-stale-value-input-fire26"
DETECTOR_SEVERITY_DEFAULT = "Medium"

_SKIP_NAME_RE = re.compile(r"(?i)(?:test|mock|fixture|harness|setup|helper)")
_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public)\b")
_FUNCTION_START_RE = re.compile(
    r"(?is)\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\([^)]*\)(?P<trailer>[^{;]*)\{"
)
_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:update|accrue|sync|refresh|borrow|repay|liquidat|deposit|withdraw|"
    r"redeem|mint|claim|settle|payout|price|quote|rate|convert|preview)"
)
_UTILIZATION_INPUT_RE = re.compile(
    r"(?is)\b(?:totalBorrows?|totalBorrowed|totalDebt|totalSupply|totalAssets|"
    r"cash|availableLiquidity|utilization|borrowIndex|liquidityIndex|supplyIndex)\b"
)
_RATE_OR_INDEX_WRITE_RE = re.compile(
    r"(?is)\b(?:utilization|borrowIndex|liquidityIndex|supplyIndex|exchangeRate|"
    r"interestRate|borrowRate|supplyRate|rate|index)\b\s*(?:=|\+=|-=)"
)
_ARITHMETIC_RE = re.compile(r"(?s)(?:\*|/|%)")
_REFRESH_RE = re.compile(
    r"(?is)\b(?:refreshReserve|updateReserve|syncTotalBorrow|_updateBorrowTotal|"
    r"refreshTotals|syncTotals|syncUtilization|syncLiquidity|updateIndexesBefore|"
    r"accrueBefore|accrueFirst)\s*\("
)
_BLOCKHASH_CALL_RE = re.compile(r"(?is)\bblockhash\s*\(\s*(?P<arg>[^)]+?)\s*\)")
_RECENT_BLOCKHASH_CALL_RE = re.compile(
    r"(?is)\bblockhash\s*\(\s*block\.number\s*-\s*"
    r"(?:[1-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\s*\)"
)
_BLOCKHASH_FRESHNESS_RE = re.compile(
    r"(?is)(?:block\.number\s*-\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:<=|<)\s*25[56]|"
    r"[A-Za-z_][A-Za-z0-9_]*\s*(?:>=|>)\s*block\.number\s*-\s*25[56]|"
    r"bytes32\s*\(\s*0\s*\)|BlockhashStale|staleBlock|recentBlock|MAX_STALE|"
    r"maxStale|freshnessWindow)"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:price|rate|accounting|collateral|debt|borrow|supply|share|"
    r"asset|amount|value|payout|reserve|credit|liquidity|index|fee|premium|"
    r"principal|settlement)\b"
)
_VALUE_WRITE_RE = re.compile(
    r"(?is)\b(?:accountingValue|settlementValue|collateralValue|debtValue|"
    r"borrowValue|reserveValue|credit|credits|payout|payouts|amountOut|"
    r"shares|assets|premium|fee|price|rate|index)\b"
    r"(?:\s*\[[^\]]+\]){0,3}\s*(?:=|\+=|-=)"
)


@dataclass(frozen=True)
class _FunctionSource:
    name: str
    trailer: str
    start: int
    end: int
    text: str


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _strip_comments(source: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n\r]*", "", text)


def _line_for(source: str, offset: int) -> int:
    return source.count("\n", 0, max(offset, 0)) + 1


def _find_matching_brace(source: str, open_brace: int) -> int | None:
    depth = 0
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _iter_functions(source: str) -> Iterable[_FunctionSource]:
    for match in _FUNCTION_START_RE.finditer(source):
        open_brace = source.find("{", match.start())
        if open_brace == -1:
            continue
        end = _find_matching_brace(source, open_brace)
        if end is None:
            continue
        yield _FunctionSource(
            name=match.group("name"),
            trailer=match.group("trailer") or "",
            start=match.start(),
            end=end,
            text=source[match.start():end],
        )


def _is_public_economic_function(name: str, trailer: str) -> bool:
    if not _VISIBILITY_RE.search(trailer):
        return False
    if _SKIP_NAME_RE.search(name):
        return False
    return bool(_ECONOMIC_ENTRY_RE.search(name))


def _matches_stale_utilization(source: str) -> tuple[str, int] | None:
    if _REFRESH_RE.search(source):
        return None
    if not _UTILIZATION_INPUT_RE.search(source):
        return None
    if not _RATE_OR_INDEX_WRITE_RE.search(source):
        return None
    if not _ARITHMETIC_RE.search(source):
        return None
    match = _UTILIZATION_INPUT_RE.search(source)
    return ("stale utilization or debt total feeds rate or index arithmetic", match.start() if match else 0)


def _matches_stale_blockhash_accounting(source: str) -> tuple[str, int] | None:
    if not _BLOCKHASH_CALL_RE.search(source):
        return None
    if _RECENT_BLOCKHASH_CALL_RE.search(source):
        return None
    if _BLOCKHASH_FRESHNESS_RE.search(source):
        return None
    if not _VALUE_CONTEXT_RE.search(source):
        return None
    if not (_VALUE_WRITE_RE.search(source) and _ARITHMETIC_RE.search(source)):
        return None
    match = _BLOCKHASH_CALL_RE.search(source)
    return ("stale blockhash feeds value accounting arithmetic", match.start() if match else 0)


def _classify_function_source(source: str) -> tuple[str, int] | None:
    return _matches_stale_utilization(source) or _matches_stale_blockhash_accounting(source)


def _regex_finding(source: str, file_path: str, offset: int, message: str, function_name: str | None):
    return {
        "detector": DETECTOR_NAME,
        "severity": DETECTOR_SEVERITY_DEFAULT,
        "file": file_path,
        "line": _line_for(source, offset),
        "message": (
            f"{DETECTOR_NAME}: {message}. NOT_SUBMIT_READY: detector "
            "fixture smoke evidence only."
        ),
        "function": function_name,
    }


def scan(source: str, file_path: str):
    """Regex-runner entrypoint for recall scoreboard integration."""
    text = _strip_comments(source)
    findings = []
    for function in _iter_functions(text):
        if not _is_public_economic_function(function.name, function.trailer):
            continue
        classified = _classify_function_source(function.text)
        if classified is None:
            continue
        message, relative_offset = classified
        findings.append(
            _regex_finding(
                source,
                file_path,
                function.start + relative_offset,
                message,
                function.name,
            )
        )
    return findings


class FundLossStaleValueInputFire26(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Flags stale utilization, debt totals, or old blockhash values consumed "
        "as price, rate, payout, or accounting arithmetic without freshness or "
        "current-state validation."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Stale value input feeds accounting arithmetic"
    WIKI_DESCRIPTION = (
        "A public economic function computes rates, indexes, prices, payouts, "
        "or accounting balances from a value that is only valid after a refresh "
        "or bounded freshness check. When the function skips that refresh, the "
        "computed value can permanently miscount user or protocol funds."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A lending reserve updates borrow and supply indexes from totalBorrows "
        "and totalSupply without first syncing pending debt. A second accounting "
        "path prices a settlement from blockhash(settlementBlock) without "
        "checking that the block is still within the EVM 256-block window."
    )
    WIKI_RECOMMENDATION = (
        "Refresh reserve totals before computing utilization, and reject stale "
        "blockhash inputs with a 256-block freshness window plus a nonzero "
        "blockhash check before using them in accounting math."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if _SKIP_NAME_RE.search(getattr(contract, "name", "") or ""):
                continue

            for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
                if getattr(function, "is_constructor", False):
                    continue
                visibility = str(getattr(function, "visibility", "") or "").lower()
                if visibility not in {"external", "public"}:
                    continue
                name = str(getattr(function, "name", "") or "")
                if not _ECONOMIC_ENTRY_RE.search(name) or _SKIP_NAME_RE.search(name):
                    continue

                source = _strip_comments(_source_text(function))
                classified = _classify_function_source(source)
                if classified is None:
                    continue
                message, _offset = classified
                info = [
                    function,
                    (
                        f" - {DETECTOR_NAME}: {message}. NOT_SUBMIT_READY: "
                        "detector fixture smoke evidence only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results


__all__ = [
    "FundLossStaleValueInputFire26",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "scan",
]
