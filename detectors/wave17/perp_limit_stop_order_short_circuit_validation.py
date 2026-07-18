"""
perp-limit-stop-order-short-circuit-validation

Narrow fixture-smoke detector for perp conditional order validators that reject
only when both the limit predicate and stop predicate fail:

    if (!validateLimitPrice(...) && !validateStopPrice(...)) revert;

That boolean shape short-circuits the stop validation whenever the limit
predicate succeeds, treating a limit+stop order as a plain limit order.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_CONTRACT_HINT_RE = re.compile(
    r"\b(?:LimitOrder|StopOrder|PerpOrder|TriggerOrder|conditionalOrder|"
    r"limitPrice|stopPrice|LIMIT_STOP)\b",
    re.IGNORECASE,
)
_FUNCTION_NAME_RE = re.compile(
    r"\b(?:validate|checkOrder|_?execute|fillOrder|executeOrder|matchOrder)\b",
    re.IGNORECASE,
)
_LIMIT_STOP_ORDER_RE = re.compile(
    r"\b(?:LIMIT_STOP|bothLimitAndStop|isLimitStop)\b|"
    r"\blimitPrice\b[^;{}]*(?:&&|\band\b)[^;{}]*\bstopPrice\b|"
    r"\bstopPrice\b[^;{}]*(?:&&|\band\b)[^;{}]*\blimitPrice\b",
    re.IGNORECASE | re.DOTALL,
)
_NEGATED_LIMIT_RE = re.compile(
    r"!\s*\(?\s*(?:_?validateLimit(?:Price)?\s*\(|"
    r"(?:limit(?:Price)?(?:OK|Ok|Valid)|limitOK|limitValid)\b)",
    re.IGNORECASE,
)
_NEGATED_STOP_RE = re.compile(
    r"!\s*\(?\s*(?:_?validateStop(?:Price)?\s*\(|"
    r"(?:stop(?:Price)?(?:OK|Ok|Valid)|stopOK|stopValid)\b)",
    re.IGNORECASE,
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _if_conditions(source: str):
    pos = 0
    while True:
        idx = source.find("if", pos)
        if idx == -1:
            return
        before = source[idx - 1] if idx > 0 else ""
        after = source[idx + 2] if idx + 2 < len(source) else ""
        if (before.isalnum() or before == "_") or (after.isalnum() or after == "_"):
            pos = idx + 2
            continue

        cursor = idx + 2
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor >= len(source) or source[cursor] != "(":
            pos = cursor
            continue

        start = cursor + 1
        depth = 1
        cursor += 1
        while cursor < len(source) and depth:
            char = source[cursor]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            cursor += 1
        if depth == 0:
            yield source[start : cursor - 1]
        pos = cursor


def _has_bad_short_circuit_guard(source: str) -> bool:
    for condition in _if_conditions(source):
        if "&&" not in condition:
            continue
        if not _NEGATED_LIMIT_RE.search(condition):
            continue
        if not _NEGATED_STOP_RE.search(condition):
            continue
        return True
    return False


class PerpLimitStopOrderShortCircuitValidation(AbstractDetector):
    ARGUMENT = "perp-limit-stop-order-short-circuit-validation"
    HELP = (
        "Limit+stop order validation rejects only when both negated predicates "
        "fail, so Solidity short-circuits the stop check when the limit check "
        "passes."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "perp-limit-stop-order-short-circuit-validation.yaml"
    )
    WIKI_TITLE = "Limit+stop composite order validation short-circuits stop trigger"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags conditional "
        "perp order validators that use `!validateLimitPrice(...) && "
        "!validateStopPrice(...)` for LIMIT_STOP orders, causing the stop "
        "predicate to be skipped whenever the limit predicate succeeds."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A filler submits a LIMIT_STOP order while the limit price is satisfied "
        "but the stop trigger has not fired. The bad guard evaluates "
        "`!true && ?`, short-circuits before checking the stop trigger, and "
        "allows execution as though the order were a plain limit order."
    )
    WIKI_RECOMMENDATION = (
        "Reject when either predicate fails: `if (!validateLimitPrice(...) || "
        "!validateStopPrice(...)) revert();`, or require both positive "
        "predicates to hold. Keep this row NOT_SUBMIT_READY until corpus-backed "
        "exploit evidence is added."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_of(contract)
            if not _CONTRACT_HINT_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public", "internal"}:
                    continue
                if not _FUNCTION_NAME_RE.search(getattr(function, "name", "") or ""):
                    continue

                source = _source_of(function)
                if not source:
                    continue
                if not _LIMIT_STOP_ORDER_RE.search(source):
                    continue
                if not _has_bad_short_circuit_guard(source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " validates a limit+stop order with a double-negation && "
                    "guard, so the stop predicate short-circuits when the limit "
                    "predicate succeeds.\n",
                ]
                results.append(self.generate_result(info))

        return results
