"""
moonbeam-frontier-msgvalue-128bit-truncation

Narrow fixture-smoke detector for the Frontier EVM/runtime boundary class:
a payable wrapper observes full EVM `msg.value`, while the runtime-side amount
is explicitly narrowed to u128/uint128 without a range or fallible-conversion
guard.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_BOUNDARY_HINT_RE = re.compile(
    r"\b(frontier|substrate|pallet|runtime|native|u128|uint128|low_u128)\b",
    re.IGNORECASE,
)
_MSG_VALUE_U128_TRUNCATION_RE = re.compile(
    r"\buint128\s*\(\s*msg\.value\s*\)|"
    r"\bmsg_value\s*(?:as\s+u128|\.low_u128\s*\(\s*\))|"
    r"\bas\s+u128\b",
    re.IGNORECASE,
)
_FULL_MSG_VALUE_CREDIT_RE = re.compile(
    r"_mint\w*\s*\([^;]*\bmsg\.value\b|"
    r"\b(?:wrapped\w*|totalWrapped\w*|minted\w*|shares\w*|balances?)\b"
    r"(?:\s*\[[^\]]+\])?\s*(?:\+=|=)\s*[^;]*\bmsg\.value\b",
    re.IGNORECASE | re.DOTALL,
)
_VISIBLE_U128_GUARD_RE = re.compile(
    r"\bmsg\.value\s*<=\s*type\s*\(\s*uint128\s*\)\s*\.\s*max\b|"
    r"\btype\s*\(\s*uint128\s*\)\s*\.\s*max\s*>=\s*msg\.value\b|"
    r"\b(?:SafeCast\.)?toUint128\s*\(\s*msg\.value\s*\)|"
    r"\btry_into\b|\btryInto\b|\bchecked_as_u128\b|\bAmountOverflow\b|"
    r"\bValueOverflow\b|\bBalanceOverflow\b",
    re.IGNORECASE | re.DOTALL,
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class MoonbeamFrontierMsgvalue128bitTruncation(AbstractDetector):
    ARGUMENT = "moonbeam-frontier-msgvalue-128bit-truncation"
    HELP = (
        "Frontier-style payable wrapper narrows `msg.value` to u128/uint128 "
        "while also crediting the full EVM msg.value, without an overflow guard"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "moonbeam-frontier-msgvalue-128bit-truncation.yaml"
    )
    WIKI_TITLE = "Frontier EVM msg.value to u128 truncation source-shape"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags a payable "
        "Frontier/Substrate bridge or wrapper shape where `msg.value` is "
        "explicitly narrowed to u128/uint128 for the runtime leg while the "
        "full EVM `msg.value` is separately credited or minted."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "If an EVM wrapper credits full U256 msg.value but the native runtime "
        "leg truncates that same value to u128, a value such as 2^128 can "
        "become zero on the runtime leg while still minting/crediting the "
        "wrapper balance."
    )
    WIKI_RECOMMENDATION = (
        "Reject values above u128 before crossing the runtime boundary, or use "
        "a fallible conversion such as try_into/toUint128 that reverts on "
        "overflow before any mint or credit based on msg.value."
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
            if not _BOUNDARY_HINT_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if not getattr(function, "payable", False):
                    continue

                source = _source_of(function)
                if not source or "msg.value" not in source:
                    continue
                if not _MSG_VALUE_U128_TRUNCATION_RE.search(source):
                    continue
                if not _FULL_MSG_VALUE_CREDIT_RE.search(source):
                    continue
                if _VISIBLE_U128_GUARD_RE.search(source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " narrows msg.value to u128/uint128 for a Frontier-style "
                    "runtime leg while also crediting the full EVM msg.value "
                    "without a visible overflow guard.\n",
                ]
                results.append(self.generate_result(info))

        return results
