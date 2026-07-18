"""
interest-accrual-view-uses-stale-index — generated from reference/patterns.dsl/interest-accrual-view-uses-stale-index.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py interest-accrual-view-uses-stale-index.yaml
Source: solodit/interest-accrual-stale-view-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InterestAccrualViewUsesStaleIndex(AbstractDetector):
    ARGUMENT = "interest-accrual-view-uses-stale-index"
    HELP = "View-only share-price / totalAssets / maxWithdraw function returns a value computed from a stale interest index; it does not extrapolate accrued interest since the last update, so integrators read numbers below the user's actual entitlement."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/interest-accrual-view-uses-stale-index.yaml"
    WIKI_TITLE = "Interest-accrual view uses stale index (no extrapolation since last update)"
    WIKI_DESCRIPTION = "The contract maintains an interest / reward / liquidity index (interestIndex, accRewardPerShare, liquidityIndex, totalBorrow, cumulativeIndex) that is only advanced when a mutating call (deposit, borrow, repay, accrue) runs. A view-only function — totalAssets, convertToAssets, convertToShares, maxWithdraw, maxRedeem, sharePrice, getBalance — reads the cached index directly without adding the inter"
    WIKI_EXPLOIT_SCENARIO = "A yield aggregator polls vault.totalAssets() every block to rebalance. Between blocks N and N+K no user interacts with the vault, so interestIndex never advances. totalAssets() returns assets*interestIndex_old / RAY instead of assets*(interestIndex_old + deltaIndex_since_lastUpdate)/RAY, under-reporting vault NAV by deltaIndex*assets. The aggregator either (a) rejects profitable rebalances because"
    WIKI_RECOMMENDATION = "Every view that returns an index-driven value must first compute the index *as if* accrual had run up to block.timestamp. Factor the interest-rate model into a pure helper (e.g. `_simulatedIndex()`) and have both the mutating accrual and every affected view call it. Add the pendingInterest component"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.name_matches': '^(totalAssets|convertToAssets|convertToShares|maxWithdraw|maxRedeem|_totalAssets|getBalance|sharePrice)$'}, {'function.body_contains_regex': '(interestIndex|accRewardPerShare|liquidityIndex|totalBorrow|cumulativeIndex)'}, {'function.body_not_contains_regex': '(\\+\\s*accruedSince|timeSinceLastUpdate|block\\.timestamp\\s*-\\s*lastUpdate|pendingInterest)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — interest-accrual-view-uses-stale-index: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
