"""
Fixture-smoke detector for options-uncapped-position-count-makes-account-unliquidatable.

This row intentionally stays NOT_SUBMIT_READY: it proves a narrow source shape
only, not a corpus-backed exploit. The detector requires a liquidation/health
function that iterates over an account position list and a contract that appends
to such a list without an evident max-position cap.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract  # noqa: E402

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OptionsUncappedPositionCountMakesAccountUnliquidatable(AbstractDetector):
    ARGUMENT = "options-uncapped-position-count-makes-account-unliquidatable"
    HELP = (
        "Liquidation or health-check iterates over an account's unbounded "
        "position list, allowing position-count gas DoS."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "options-uncapped-position-count-makes-account-unliquidatable.yaml"
    )
    WIKI_TITLE = "Liquidation iterates an uncapped account position list"
    WIKI_DESCRIPTION = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only. The detector "
        "matches contracts where users can append option/portfolio positions "
        "and liquidation or health-check logic loops over the whole list with "
        "no visible max-position guard."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An account opens many dust-sized option legs. When the account becomes "
        "unsafe, liquidation has to value or settle every leg in one call, so "
        "gas scales with the attacker-controlled position count and can exceed "
        "the block gas limit."
    )
    WIKI_RECOMMENDATION = (
        "Cap positions per account at open/mint time and add liquidation paths "
        "that can safely process bounded subsets. Promote only after corpus "
        "evidence proves protocol-specific exploitability."
    )

    _LIQUIDATION_NAME_RE = re.compile(
        r"(?:liquidat|health|solven|portfolio|collateral|premium|bankrupt)",
        re.IGNORECASE,
    )
    _POSITION_APPEND_RE = re.compile(
        r"\b(?:positionIdList|positionList|positionIds|positions|_positions|accountPositions)"
        r"(?:\s*\[[^\]]+\])?\s*\.\s*push\s*\(",
        re.IGNORECASE | re.DOTALL,
    )
    _POSITION_LOOP_RE = re.compile(
        r"for\s*\([^;]*;[^;]*\b(?:positionIdList|positionList|positionIds|positions|"
        r"_positions|accountPositions)(?:\s*\[[^\]]+\])?\s*\.\s*length\b",
        re.IGNORECASE | re.DOTALL,
    )
    _LIQUIDATION_BODY_RE = re.compile(
        r"(?:liquidat|health|solven|premium|collateral|portfolio|settle|bankrupt|"
        r"positionBalance|positionHash|oracle)",
        re.IGNORECASE,
    )
    _POSITION_CAP_RE = re.compile(
        r"(?:MAX_(?:OPEN_)?POSITIONS|MAX_POSITIONS_PER_ACCOUNT|TooManyPositions|"
        r"require\s*\([^;]*(?:positionIdList|positionList|positionIds|positions|"
        r"_positions|accountPositions)[^;]*\.length[^;]*(?:MAX_|[0-9]+)[^;]*\)|"
        r"(?:positionIdList|positionList|positionIds|positions|_positions|accountPositions)"
        r"[^;]*\.length\s*(?:<=|<|>=|>)\s*(?:MAX_|[0-9]+))",
        re.IGNORECASE | re.DOTALL,
    )

    _INCLUDE_LEAF_HELPERS = True
    _INVERSE_CEI = False

    @classmethod
    def _contract_source(cls, contract) -> str:
        try:
            return contract.source_mapping.content or ""
        except Exception:
            return ""

    @classmethod
    def _function_source(cls, function) -> str:
        try:
            return function.source_mapping.content or ""
        except Exception:
            return ""

    @classmethod
    def _contract_has_uncapped_position_growth(cls, contract) -> bool:
        src = cls._contract_source(contract)
        if not cls._POSITION_APPEND_RE.search(src):
            return False
        return not cls._POSITION_CAP_RE.search(src)

    @classmethod
    def _function_matches(cls, function) -> bool:
        visibility = getattr(function, "visibility", "") or ""
        if visibility not in {"external", "public", "internal"}:
            return False
        name = getattr(function, "name", "") or ""
        src = cls._function_source(function)
        if not cls._LIQUIDATION_NAME_RE.search(name + "\n" + src):
            return False
        if not cls._POSITION_LOOP_RE.search(src):
            return False
        return bool(cls._LIQUIDATION_BODY_RE.search(src))

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not self._contract_has_uncapped_position_growth(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._function_matches(function):
                    continue
                info = [
                    function,
                    " -- options-uncapped-position-count-makes-account-unliquidatable: "
                    "uncapped account position list is iterated by liquidation/health logic.",
                ]
                results.append(self.generate_result(info))
        return results
