"""
a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect — generated from reference/patterns.dsl/a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousUserCanReduceOtherUsersRewardsDueToIncorrect(AbstractDetector):
    ARGUMENT = "a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect"
    HELP = "A malicious user can reduce other users' rewards due to incorrect accounting of stake balances"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect.yaml"
    WIKI_TITLE = "A malicious user can reduce other users' rewards due to incorrect accounting of stake balances"
    WIKI_DESCRIPTION = "**Update**\nMarked as \"Fixed\" by the client. Addressed in: `639134848b30d20ec3293c78c5e99c21ece6c096`.\n\n**File(s) affected:**`contracts-v3/LibTokenizedVaultStaking.sol`\n\n**Description:** In the function `_unstake()`, the stake balance of the entity is not reduced for the current interval, namely `s.s"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #59474: **Update**\nMarked as \"Fixed\" by the client. Addressed in: `639134848b30d20ec3293c78c5e99c21ece6c096`.\n\n**File(s) affected:**`contracts-v3/LibTokenizedVaultStaking.sol`\n\n**Description:** In the functio"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '(?i).*(stakeBalance).*'}, {'function.reads_state_var_matching_regex': '(?i).*(stakeBalance).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.does_not_call_matching_regex': '(?i).*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-malicious-user-can-reduce-other-users-rewards-due-to-incorrect: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
