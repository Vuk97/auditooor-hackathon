"""
compound-v2-reward-index-strict-inequality-claim-skip — generated from reference/patterns.dsl/compound-v2-reward-index-strict-inequality-claim-skip.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py compound-v2-reward-index-strict-inequality-claim-skip.yaml
Source: auditooor-R71-fixdiff-mined-compound-protocol-fcf067f6fa
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CompoundV2RewardIndexStrictInequalityClaimSkip(AbstractDetector):
    ARGUMENT = "compound-v2-reward-index-strict-inequality-claim-skip"
    HELP = "Reward-distribution helper uses strict `>` (instead of `>=`) when comparing the market's global index to `compInitialIndex`. For markets whose index was never advanced past the initial value, the branch never fires, so fresh suppliers/borrowers with a zero user-index never get seeded and miss an ent"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/compound-v2-reward-index-strict-inequality-claim-skip.yaml"
    WIKI_TITLE = "Reward distribution uses strict > instead of >= against initial index"
    WIKI_DESCRIPTION = "Compound-style reward distribution seeds a new user with rewards accrued since the market's 'reward activation' moment. The canonical pattern is: `if (userIndex == 0 && marketIndex > initialIndex) userIndex = initialIndex;`. The strict `>` (instead of `>=`) breaks the equality case — for markets where the global index is exactly `initialIndex` (common for brand-new markets where no-one has yet cal"
    WIKI_EXPLOIT_SCENARIO = "Compound Proposal 64 (commit fcf067f6fa) fixed exactly this: `if (supplierIndex == 0 && supplyIndex > compInitialIndex)` became `if (supplierIndex == 0 && supplyIndex >= compInitialIndex)`. Before the fix, any user supplying to a new market (where `supplyIndex == compInitialIndex == 1e36`) never got seeded; their `compSupplierIndex` stayed at zero. On the next accrual, `deltaIndex = supplyIndex - "
    WIKI_RECOMMENDATION = "Every 'is-user-initial' branch that compares the market index to a base constant must use non-strict inequality: `if (userIndex == 0 && marketIndex >= INITIAL_INDEX) userIndex = INITIAL_INDEX;`. Better, factor the seed into a dedicated helper `_seedUserIndex(user, marketIndex)` that makes the bounda"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'compInitialIndex|compSupplierIndex|compBorrowerIndex|distributeSupplierComp|distributeBorrowerComp'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '^(distributeSupplierComp|distributeBorrowerComp|_distributeSupplier|_distributeBorrower|updateRewardIndex)$'}, {'function.body_contains_regex': 'supplierIndex\\s*==\\s*0|borrowerIndex\\s*==\\s*0|userIndex\\s*==\\s*0'}, {'function.body_contains_regex': 'supplyIndex\\s*>\\s*\\w+InitialIndex|borrowIndex\\s*>\\s*\\w+InitialIndex|globalIndex\\s*>\\s*INITIAL_INDEX'}, {'function.body_not_contains_regex': 'supplyIndex\\s*>=\\s*\\w+InitialIndex|borrowIndex\\s*>=\\s*\\w+InitialIndex|globalIndex\\s*>=\\s*INITIAL_INDEX'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — compound-v2-reward-index-strict-inequality-claim-skip: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
