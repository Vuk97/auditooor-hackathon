"""
bulk-burn-calculates-rewards-against-stale-total-supply - generated from reference/patterns.dsl/bulk-burn-calculates-rewards-against-stale-total-supply.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bulk-burn-calculates-rewards-against-stale-total-supply.yaml
Source: auditooor-known-limitation-burndown
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BulkBurnCalculatesRewardsAgainstStaleTotalSupply(AbstractDetector):
    ARGUMENT = "bulk-burn-calculates-rewards-against-stale-total-supply"
    HELP = "Bulk burn path snapshots totalSupply before the burn loop and calculates rewards against that stale denominator."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bulk-burn-calculates-rewards-against-stale-total-supply.yaml"
    WIKI_TITLE = "Bulk burn reward math uses pre-burn totalSupply"
    WIKI_DESCRIPTION = "A batch burn/redeem function reads totalSupply before entering a loop, calculates each user's reward from that stale supply snapshot, and then burns shares/tokens. After the first burn the denominator is outdated, so later reward allocations no longer reflect the live supply."
    WIKI_EXPLOIT_SCENARIO = "A protocol distributes pending rewards during bulkBurn(). It snapshots supply at 100 shares, pays account A, burns A's 40 shares, then still pays account B as if supply were 100 instead of 60. Depending on the formula, later users can be underpaid or excess rewards remain/are misallocated."
    WIKI_RECOMMENDATION = "Burn or aggregate all burn amounts before reward allocation, or recompute the denominator after each burn. If a snapshot is intended, document it and make the accounting invariant explicit in tests."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bulk|batch|multi|many).*(burn|redeem|withdraw)|reward|totalSupply|_totalSupply'}, {'contract.has_state_var_matching': '(?i)(totalSupply|_totalSupply|reward|rewards|pending|claimable)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)((bulk|batch|multi|many).*(burn|redeem|withdraw)|(burn|redeem|withdraw).*(bulk|batch|multi|many))'}, {'function.body_contains_regex': '(?i)(for\\s*\\(|while\\s*\\()'}, {'function.body_contains_regex': '(?i)(totalSupply|_totalSupply)'}, {'function.body_contains_regex': '(?i)(reward|rewards|pending|claimable)'}, {'function.body_contains_regex': '(?i)(totalSupply|_totalSupply)[\\s\\S]{0,1200}(reward|rewards|pending|claimable)\\w*\\s*=\\s*[^;]*(supplySnapshot|totalSupply|_totalSupply)[\\s\\S]{0,1200}(_burn\\s*\\(|burn\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(postBurnSupply|supplyAfterBurn|afterBurnSupply|supplyAfter|remainingSupply)\\s*='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - bulk-burn-calculates-rewards-against-stale-total-supply: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
