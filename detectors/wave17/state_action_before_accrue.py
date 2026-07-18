"""
state-action-before-accrue — generated from reference/patterns.dsl/state-action-before-accrue.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py state-action-before-accrue.yaml
Source: auto-mined-from-diffs/added-accrue-first-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StateActionBeforeAccrue(AbstractDetector):
    ARGUMENT = "state-action-before-accrue"
    HELP = "User-facing lending action (supply/borrow/redeem/repay/liquidate) mutates principal-denominated state without calling accrueInterest / _updateIndex first. The action snapshots a stale index and mis-prices the user's position."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/state-action-before-accrue.yaml"
    WIKI_TITLE = "Missing accrue-first invariant: action executes against stale index"
    WIKI_DESCRIPTION = "Index-based lending accounting (Compound v2, Aave v2, Morpho, cToken-derivative contracts) converts principal balances to underlying via a timestamp-dependent multiplier — `borrowIndex`, `supplyIndex`, or `exchangeRate`. The contract-wide invariant is that every action which reads or writes principal-denominated storage MUST first call `accrueInterest()` (or equivalent `_updateIndex`, `_accrue`, `"
    WIKI_EXPLOIT_SCENARIO = "A Compound-style market implements `redeem(uint256 redeemTokens)` by computing `redeemAmount = redeemTokens * exchangeRateStored / 1e18` and transferring the underlying. The function does not call `accrueInterest()` first. `exchangeRateStored` was last updated 50 blocks ago at a lower value. A supplier calls `redeem(myBalance)`; the function uses the stale (low) rate, computes a too-small `redeemA"
    WIKI_RECOMMENDATION = "Add a `nonReentrant` + accrue-first modifier such as `modifier accrues() { accrueInterest(); _; }` and apply it to every external/public function that reads or mutates principal-denominated state: supply, deposit, mint, redeem, redeemUnderlying, withdraw, borrow, repay, repayBorrow, liquidate, liqui"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'accrueInterest|_accrue|updateIndex|_updateIndex|borrowIndex|supplyIndex|exchangeRate|interestRateModel'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.not_slither_synthetic': True}, {'function.name_matches': '^(supply|deposit|mint|redeem|redeemUnderlying|withdraw|borrow|repay|repayBorrow|liquidate|liquidateBorrow|seize|transfer|transferFrom)$'}, {'function.body_not_contains_regex': 'accrueInterest\\s*\\(|_accrue\\s*\\(|_updateIndex\\s*\\(|updateIndex\\s*\\(|_harvest\\s*\\(|_syncIndex'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — state-action-before-accrue: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
