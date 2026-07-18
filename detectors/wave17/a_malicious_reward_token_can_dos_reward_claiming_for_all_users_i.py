"""
a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i — generated from reference/patterns.dsl/a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousRewardTokenCanDosRewardClaimingForAllUsersI(AbstractDetector):
    ARGUMENT = "a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i"
    HELP = "A malicious reward token can DoS reward claiming for all users in a vault"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i.yaml"
    WIKI_TITLE = "A malicious reward token can DoS reward claiming for all users in a vault"
    WIKI_DESCRIPTION = "## Vulnerability Report\n\n## Severity\n**Medium Risk**\n\n## Context\nMultiRewards.sol#L231-L240\n\n## Summary\nA malicious reward token can DoS reward claims for all users in a vault to which it is added. This affects the claiming process for all the reward tokens because they are transferred in a loop, wh"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #49852: ## Vulnerability Report\n\n## Severity\n**Medium Risk**\n\n## Context\nMultiRewards.sol#L231-L240\n\n## Summary\nA malicious reward token can DoS reward claims for all users in a vault to which it is added. Th"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = []
    _MATCH = [{'function.name_matches': '.*(getRewardForUser|rewardTokens).*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(getRewardForUser|rewardTokens).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-malicious-reward-token-can-dos-reward-claiming-for-all-users-i: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
