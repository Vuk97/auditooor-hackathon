"""
interest-rate-update-stale-utilization — generated from reference/patterns.dsl/interest-rate-update-stale-utilization.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py interest-rate-update-stale-utilization.yaml
Source: solodit/C0328
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InterestRateUpdateStaleUtilization(AbstractDetector):
    ARGUMENT = "interest-rate-update-stale-utilization"
    HELP = "Interest-rate/index update reads `totalBorrows` / `totalSupply` for the utilization ratio without refreshing them first, so rate and accrued interest are computed from stale values — mispricing borrow/supply indexes."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/interest-rate-update-stale-utilization.yaml"
    WIKI_TITLE = "Interest-rate update uses stale utilization / debt totals"
    WIKI_DESCRIPTION = "Lending protocol index and rate update functions (e.g., `_updateIndexes`, `accrueInterest`, `_updateInterestRatesAndLiquidity`) feed `totalBorrows`, `totalSupply`, or a derived utilization ratio into the rate formula. If the function does not first refresh the reserve's outstanding debt (accrue interest on prior borrow index, pull pending flashloan/liquidation deltas, re-read totals after external"
    WIKI_EXPLOIT_SCENARIO = "At T0 the reserve has totalBorrows=100, lastAccrual=T0. At T1 a large borrow increases totalBorrows to 500 but the protocol only re-reads the state var after the stale-utilization-based rate has been multiplied by the elapsed window. The index update treats the entire T0→T1 interval as if utilization were the T0 value, under-accruing borrower interest (and over-accruing suppliers via symmetric err"
    WIKI_RECOMMENDATION = "Refresh the reserve's totalBorrows/totalSupply immediately before computing utilization: call `accrueInterest` on the prior index first, then read the totals, then compute the new rate and index. Assert the `lastUpdatedTimestamp` invariant is advanced atomically with every totals-mutating path (borr"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(totalBorrows|totalBorrowed|utilization|borrowIndex|liquidityIndex|supplyIndex)'}, {'contract.has_state_declaration_matching': '(totalBorrows|totalBorrowed|borrowIndex|liquidityIndex|supplyIndex)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(updateInterest|updateState|_updateStates|updateIndexes|_updateIndexes|accrueInterest|updateRates|_updateInterestRatesAndLiquidity)'}, {'function.body_contains_regex': {'regex': '(totalBorrow|utilization|\\btotalSupply\\b|\\btotalDebt\\b)'}}, {'function.body_not_contains_regex': {'regex': '(refreshReserve|updateReserve|syncTotalBorrow|_updateBorrowTotal|accrue.*before|accrue.*first)'}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — interest-rate-update-stale-utilization: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
