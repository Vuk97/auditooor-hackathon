"""
Permissionless oracle latest-value read without dispute-window wait.

Row-local repair only. This detector intentionally stays narrow and proves just
the owned fixture shape: a public/external borrow-like entrypoint reads a
Tellor-style `getCurrentValue(queryId)` result, uses that returned price in the
same function, and shows no visible `getDataBefore(...)` or dispute-window age
check before acting on the price.

Submission posture: NOT_SUBMIT_READY. The proof is fixture-smoke/source-shape
only and does not claim broad optimistic-oracle coverage.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


_BORROW_LIKE_NAME_RE = re.compile(
    r"^(?:borrow|mint|openTrove|drawDebt|increaseDebt|borrowAgainstCollateral)$",
    re.IGNORECASE,
)
_TELLOR_INTERFACE_RE = re.compile(
    r"\binterface\s+I?Tellor\b|\bI?Tellor\s+(?:public|private|internal|immutable)\b",
    re.IGNORECASE,
)
_LATEST_VALUE_RE = re.compile(r"\bgetCurrentValue\s*\(", re.IGNORECASE)
_SAFE_HISTORICAL_RE = re.compile(r"\bgetDataBefore\s*\(", re.IGNORECASE)
_REPORT_TIME_BIND_RE = re.compile(
    r"\(\s*bool\s+\w+\s*,\s*uint(?:256)?\s+(?P<price>\w+)\s*,\s*uint(?:256)?\s+(?P<time>\w+)\s*\)"
    r"\s*=\s*\w+\s*\.\s*getCurrentValue\s*\(",
    re.IGNORECASE,
)
_PRICE_USE_TEMPLATE = r"\b{price}\b[^;{{}}]*(?:/|\*|>=|<=|>|<|\+|-)|(?:/|\*|>=|<=|>|<|\+|-)[^;{{}}]*\b{price}\b"
_AGE_CHECK_TEMPLATE = (
    r"block\.timestamp\s*-\s*{time}\s*>=\s*(?:disputeWindow|DISPUTE_WINDOW|15\s*minutes|900)"
)


class PermissionlessOracleSubmitvalueUsedInstantlyNoDisputeWindow(AbstractDetector):
    ARGUMENT = "permissionless-oracle-submitvalue-used-instantly-no-dispute-window"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags the "
        "owned borrow-like path that reads Tellor-style `getCurrentValue` and "
        "uses that price immediately without a visible dispute-window wait."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "permissionless-oracle-submitvalue-used-instantly-no-dispute-window.yaml"
    )
    WIKI_TITLE = "Borrow path consumes Tellor latest value without dispute-window wait"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row proves only the owned "
        "Tellor-style borrow fixture where a public/external borrow-like "
        "entrypoint calls `getCurrentValue(queryId)`, receives `(didGet, "
        "price, reportTimestamp)`, and uses `price` in same-function "
        "collateral/debt math without a visible age gate or `getDataBefore` "
        "path. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A lending market reads a Tellor-style latest value inside `borrow`. "
        "An attacker submits an absurd price to the permissionless oracle and "
        "borrows against that transient value before the dispute window can "
        "elapse."
    )
    WIKI_RECOMMENDATION = (
        "Consume only historical/finalized oracle data, such as "
        "`getDataBefore(queryId, block.timestamp - disputeWindow)`, or apply a "
        "same-function `block.timestamp - reportTimestamp >= disputeWindow` "
        "gate before using the price. Keep this row NOT_SUBMIT_READY until "
        "evidence extends beyond the owned fixture pair."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_text(contract)
            if not _TELLOR_INTERFACE_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue

                function_name = getattr(function, "name", "") or ""
                if not _BORROW_LIKE_NAME_RE.search(function_name):
                    continue

                source = _source_text(function)
                if not source:
                    continue
                if not _LATEST_VALUE_RE.search(source):
                    continue
                if _SAFE_HISTORICAL_RE.search(source):
                    continue

                match = _REPORT_TIME_BIND_RE.search(source)
                if not match:
                    continue

                price_var = re.escape(match.group("price"))
                time_var = re.escape(match.group("time"))
                price_use_re = re.compile(_PRICE_USE_TEMPLATE.format(price=price_var), re.IGNORECASE)
                age_check_re = re.compile(_AGE_CHECK_TEMPLATE.format(time=time_var), re.IGNORECASE)

                if not price_use_re.search(source):
                    continue
                if age_check_re.search(source):
                    continue

                info = [
                    function,
                    " — permissionless-oracle-submitvalue-used-instantly-no-"
                    "dispute-window: Tellor-style latest price is consumed in "
                    "a borrow-like entrypoint without a visible dispute-window "
                    "wait. NOT_SUBMIT_READY: fixture-smoke/source-shape proof "
                    "only.",
                ]
                results.append(self.generate_result(info))
        return results
