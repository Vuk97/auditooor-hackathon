"""
pdt-can-be-set-as-a-reward-token-and-withdrawn-by-admin — generated from reference/patterns.dsl/pdt-can-be-set-as-a-reward-token-and-withdrawn-by-admin.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pdt-can-be-set-as-a-reward-token-and-withdrawn-by-admin.yaml
Source: zellic-audit-pdt-staking-v2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PdtCanBeSetAsARewardTokenAndWithdrawnByAdmin(AbstractDetector):
    ARGUMENT = "pdt-can-be-set-as-a-reward-token-and-withdrawn-by-admin"
    HELP = "Fixture-smoke heuristic for a PDT staking contract that lets admins register reward tokens without excluding the staking/PDT asset and also exposes an admin token-withdraw path that lacks the same exclusion."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pdt-can-be-set-as-a-reward-token-and-withdrawn-by-admin.yaml"
    WIKI_TITLE = "PDT can be set as a reward token and withdrawn by admin"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves the owned PDT staking shape where `registerNewRewardToken(address)` updates reward-token state without excluding the staking/PDT asset, while an admin `withdrawRewardToken`/rescue path in the same contract also omits that exclusion. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A token manager registers PDT itself as a reward token. Because the same contract also allows admin token withdrawals without rejecting PDT, an admin-controlled reward-handling flow can remove pooled staking principal under the guise of reward-token operations."
    WIKI_RECOMMENDATION = "Reject the staking/PDT asset in both reward-token registration and admin rescue/withdraw flows. Add tests that assert `newRewardToken != pdtToken` and `token != pdtToken`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)register.*reward.*token|add.*reward.*token|set.*reward.*token'}, {'function.body_contains_regex': '(?i)rewardTokenList\\.push|isRewardToken\\['}, {'function.body_not_contains_regex': '(?i)pdtToken|stakingToken|stakeToken'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pdt-can-be-set-as-a-reward-token-and-withdrawn-by-admin: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
