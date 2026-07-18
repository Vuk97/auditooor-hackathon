"""
perp-funding-state-not-updated-before-pool-mutation — generated from reference/patterns.dsl/perp-funding-state-not-updated-before-pool-mutation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-funding-state-not-updated-before-pool-mutation.yaml
Source: auditooor-R73-fixdiff-mined-gmx-synthetics-25e8e94441
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpFundingStateNotUpdatedBeforePoolMutation(AbstractDetector):
    ARGUMENT = "perp-funding-state-not-updated-before-pool-mutation"
    HELP = "Pool-mutation path (withdraw from impact pool, rebalance, settle impact) changes the denominators of funding calculations but does not call updateFundingAndBorrowingState first. Next funding accrual is computed against mutated state — misallocated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-funding-state-not-updated-before-pool-mutation.yaml"
    WIKI_TITLE = "Funding state not updated before mutating impact / virtual pool"
    WIKI_DESCRIPTION = "Perps that use an adaptive funding rate compute the rate from `diff(longOI, shortOI) / totalOI` and a position impact pool that absorbs imbalance. Any admin / keeper action that mutates those quantities (withdrawFromPositionImpactPool, shift, rebalance) must accrue funding for the period up to the mutation BEFORE changing the numbers, otherwise the interval accrues funding against post-mutation st"
    WIKI_EXPLOIT_SCENARIO = "(1) Impact pool holds 10_000 USDC. Long OI is 8M, short OI is 5M. Funding has not been accrued for 6 hours. (2) Admin calls `withdrawFromPositionImpactPool` to withdraw 9_000 USDC to treasury. State now mutated. (3) Next user opens a position, which triggers funding accrual for the entire 6-hour interval. Funding is computed against the NEW (post-withdraw) impact pool balance, not the average that"
    WIKI_RECOMMENDATION = "Any function that writes to `positionImpactPool`, `openInterest`, `virtualTokenAmount`, or `virtualInventoryForPositions` must begin with `updateFundingAndBorrowingState(...)` (or the protocol's equivalent). Treat funding accrual like ERC4626 share-price accrual: accrue BEFORE every state change. Ad"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(fundingRate|cumulativeFunding|positionImpactPool|virtualInventory|longOpenInterest|shortOpenInterest)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(withdrawFromPositionImpactPool|addToImpactPool|updateImpactPool|rebalancePool|applyPositionImpact|settleFunding)'}, {'function.body_contains_regex': '(positionImpactPool|impactPoolAmount|virtualTokenAmount|longOpenInterest|shortOpenInterest)\\s*[-+]?=|transferOut|mint|burn'}, {'function.body_not_contains_regex': 'updateFundingAndBorrowingState|updateFundingState|_settleFunding|_accrueFunding'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-funding-state-not-updated-before-pool-mutation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
