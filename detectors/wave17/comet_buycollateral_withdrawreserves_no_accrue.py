"""
comet-buycollateral-withdrawreserves-no-accrue — generated from reference/patterns.dsl/comet-buycollateral-withdrawreserves-no-accrue.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-buycollateral-withdrawreserves-no-accrue.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-724017262
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometBuycollateralWithdrawreservesNoAccrue(AbstractDetector):
    ARGUMENT = "comet-buycollateral-withdrawreserves-no-accrue"
    HELP = "Reserve-consuming flow (buyCollateral / withdrawReserves / absorb) reads getReserves or totalsBasic without calling accrueInternal first. Because reserves are computed from the present-valued totalSupplyBase and totalBorrowBase, a stale index under-reports them and lets the governor / buyer withdraw"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-buycollateral-withdrawreserves-no-accrue.yaml"
    WIKI_TITLE = "Reserve-consuming action skips accrue-first, uses stale totalsBasic"
    WIKI_DESCRIPTION = "Reserves in a Comet-style market equal `baseToken.balanceOf(this) - presentValueSupply(baseSupplyIndex, totalSupplyBase) + presentValueBorrow(baseBorrowIndex, totalBorrowBase)`. Both terms depend on the current block's indices. Any function that consumes reserves — `withdrawReserves` (governor), `buyCollateral` (market maker path), or `absorb` / liquidation that writes new present-value math — mus"
    WIKI_EXPLOIT_SCENARIO = "In Comet, `buyCollateral` and `withdrawReserves` originally read `getReserves()` directly. Certora caught that a long inter-accrual window lets the governor withdraw interest owed to suppliers but not yet realised via accrue (commit 724017262d added `accrueInternal()` at the top of both functions). The attack pattern: (1) wait for many blocks without any user interaction — indices remain stale; (2"
    WIKI_RECOMMENDATION = "Every external mutating function that touches reserves or the totals arrays must call the contract's accrue primitive as its first non-guard statement: `if (isBuyPaused()) revert Paused(); accrueInternal();`. A defensive alternative is to eliminate the snapshot entirely by making `getReserves()` its"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'accrueInternal|accrueInterest|baseSupplyIndex|baseBorrowIndex'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '^(buyCollateral|withdrawReserves|absorb|liquidate|seize|sweep|claimReserves|rescueReserves)$'}, {'function.body_contains_regex': 'getReserves|reserves|totalReserves|baseSupplyIndex|baseBorrowIndex'}, {'function.body_not_contains_regex': 'accrueInternal\\s*\\(\\s*\\)|accrueInterest\\s*\\(\\s*\\)|_accrue\\s*\\(\\s*\\)|updateIndex\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-buycollateral-withdrawreserves-no-accrue: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
