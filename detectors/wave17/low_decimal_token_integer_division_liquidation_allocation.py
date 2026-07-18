"""
Low-decimal token integer-division liquidation allocation.

Row-local repair: keep this detector intentionally narrow and honest. The
current proof is only the owned fixture pair showing a liquidation share path
that does `product / PRECISION_FACTOR_E18 + 1` in a low-decimal collateral
context. That is source-shape evidence, not a submission-ready semantic proof.

This row must remain NOT_SUBMIT_READY until broader validation exists.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

from _template_utils import is_vendored_or_test_contract


def _source_text(obj) -> str:
    source_mapping = getattr(obj, "source_mapping", None)
    return getattr(source_mapping, "content", "") or ""


class LowDecimalTokenIntegerDivisionLiquidationAllocation(AbstractDetector):
    ARGUMENT = "low-decimal-token-integer-division-liquidation-allocation"
    HELP = (
        "Fixture-smoke heuristic for liquidation share math that uses "
        "`product / PRECISION_FACTOR_E18 + 1` in a visible 6/8-decimal "
        "collateral path."
    )
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "low-decimal-token-integer-division-liquidation-allocation.yaml"
    )
    WIKI_TITLE = "Share rounding `+1` drains value for low-decimal tokens"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row proves only the owned "
        "liquidation fixture where a low-decimal collateral path computes "
        "`cashoutShares = product / PRECISION_FACTOR_E18 + 1`. "
        "NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A liquidation helper computes a low-decimal collateral allocation as "
        "`product / PRECISION_FACTOR_E18 + 1`. Splitting a liquidation into "
        "many small slices repeatedly collects the unconditional `+1` share "
        "adder."
    )
    WIKI_RECOMMENDATION = (
        "Use a real ceil-division only when there is a remainder, such as "
        "`(product + PRECISION_FACTOR_E18 - 1) / PRECISION_FACTOR_E18`, and "
        "keep this row NOT_SUBMIT_READY until evidence expands beyond the "
        "owned fixture pair."
    )

    _CONTRACT_NAME_REGEX = re.compile(r"(?:liquidat|withdraworallocate)", re.IGNORECASE)
    _FN_NAME_REGEX = re.compile(
        r"^_?(?:withdrawOrAllocateShares|calcShares|liquidationShares|cashoutShares)$",
        re.IGNORECASE,
    )
    _LOW_DECIMAL_REGEX = re.compile(
        r"\b(?:COLLATERAL_DECIMALS|collateralDecimals|tokenDecimals)\b"
        r"[^;{}]*\b(?:6|8)\b",
        re.IGNORECASE,
    )
    _UNSAFE_ALLOC_REGEX = re.compile(
        r"\bcashoutShares\s*=\s*product\s*/\s*PRECISION_FACTOR_E18\s*\+\s*1\s*;",
        re.IGNORECASE,
    )
    _SAFE_CEIL_REGEX = re.compile(
        r"\bcashoutShares\s*=\s*\(\s*product\s*\+\s*PRECISION_FACTOR_E18\s*-\s*1\s*\)"
        r"\s*/\s*PRECISION_FACTOR_E18\s*;",
        re.IGNORECASE,
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_name = getattr(contract, "name", "") or ""
            contract_source = _source_text(contract)
            if not self._CONTRACT_NAME_REGEX.search(contract_name) and not self._CONTRACT_NAME_REGEX.search(contract_source):
                continue

            if not self._LOW_DECIMAL_REGEX.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._FN_NAME_REGEX.search(function.name):
                    continue

                source = _source_text(function)
                if not source:
                    continue
                if not self._UNSAFE_ALLOC_REGEX.search(source):
                    continue
                if self._SAFE_CEIL_REGEX.search(source):
                    continue

                info = [
                    function,
                    " — low-decimal-token-integer-division-liquidation-allocation: "
                    "low-decimal liquidation share math uses "
                    "`product / PRECISION_FACTOR_E18 + 1`. "
                    "NOT_SUBMIT_READY: fixture-smoke/source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
