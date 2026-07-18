"""
halborn-liquity-fork-redemption-hint-icr-unordered — generated from reference/patterns.dsl/halborn-liquity-fork-redemption-hint-icr-unordered.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py halborn-liquity-fork-redemption-hint-icr-unordered.yaml
Source: auditooor-R75-halborn-LiquityForks-Anvil-ICR-ordering
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HalbornLiquityForkRedemptionHintIcrUnordered(AbstractDetector):
    ARGUMENT = "halborn-liquity-fork-redemption-hint-icr-unordered"
    HELP = "Liquity fork walks `SortedTroves` from lowest ICR for redemption but never re-inserts troves whose pending-rewards application lifts their live ICR above neighbors — redemption may burn a trove that is no longer the lowest-ICR, or skip the true lowest."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/halborn-liquity-fork-redemption-hint-icr-unordered.yaml"
    WIKI_TITLE = "Liquity-fork redemption iterates SortedTroves without re-sorting after pending-reward accrual"
    WIKI_DESCRIPTION = "Liquity and forks (Anvil, Beraborrow, ThresholdBTC) store troves in a `SortedTroves` linked list ordered by nominal ICR. Redemption walks from lowest ICR upward, partially or fully redeeming each trove's debt and receiving ETH/collateral pro-rata. Before redeeming a trove, the contract applies pending liquidation rewards via `_applyPendingRewards` — this can lift the trove's EFFECTIVE ICR material"
    WIKI_EXPLOIT_SCENARIO = "Anvil fork of Liquity: Bob's trove has nominal ICR=110%, pending rewards would raise it to 135%. Alice's trove has nominal ICR=115%, no pending rewards (true 115%). Redemption walks from lowest nominal first: Bob. `_applyPendingRewards` runs, Bob's debt and coll increase, effective ICR now 135%. The redemption code redeems against Bob anyway (based on the old position in the list). Bob is forced t"
    WIKI_RECOMMENDATION = "After `_applyPendingRewards(borrower)` inside the redemption loop, recompute ICR and call `_reInsert(borrower, newICR, ...)`. If the re-inserted position is no longer at the head of the sorted list, break the current redemption iteration (or move to the new `getLast()`). Maintain invariant: at the t"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Redemption|SortedTroves|TroveManager|redeemCollateral|Liquity|Anvil'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'redeemCollateral|_redeemCollateralFromTrove|getRedemptionHints|_applyPendingRewards'}, {'function.body_contains_regex': 'getLast\\s*\\(\\s*\\)|sortedTroves\\.getLast|_getCurrentICR|_getICR'}, {'function.body_contains_regex': 'while\\s*\\([^)]*\\)\\s*\\{[^}]*getPrev|for\\s*\\([^)]*\\)\\s*\\{[^}]*getPrev'}, {'function.body_not_contains_regex': '_getCurrentICR\\s*\\([^)]*\\)[^;]*>=\\s*_getCurrentICR\\s*\\(\\s*getPrev|_reInsert\\s*\\(.*ICR|requireSortedByICR'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — halborn-liquity-fork-redemption-hint-icr-unordered: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
