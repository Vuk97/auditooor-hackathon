"""
r74-reward-extra-tokens-unreachable — generated from reference/patterns.dsl/r74-reward-extra-tokens-unreachable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-reward-extra-tokens-unreachable.yaml
Source: r74b-cross-firm-cs+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74RewardExtraTokensUnreachable(AbstractDetector):
    ARGUMENT = "r74-reward-extra-tokens-unreachable"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: harvest distributes only registered reward tokens, so unexpected reward inflows can remain stranded in the strategy."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-reward-extra-tokens-unreachable.yaml"
    WIKI_TITLE = "Extra / unregistered reward tokens stranded in strategy contract"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row targets a strategy/vault harvest path that iterates `rewardTokens[]` and transfers only those registered rewards. If the contract later receives an unexpected reward token, such as a retroactive airdrop or a newly enabled gauge incentive, the token accumulates without any explicit forwarding, registration, or sweep path."
    WIKI_EXPLOIT_SCENARIO = "A farming strategy harvests CRV and CVX by looping over `rewardTokens`. Months later the gauge distributor starts emitting a third token to the same strategy address. Because `harvest()` still only iterates the original registry and exposes no extra-reward path, the new reward balance grows indefinitely and never reaches depositors."
    WIKI_RECOMMENDATION = "Keep the submission posture NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair. For the code shape itself, pair the fixed reward registry with an explicit extra-reward path such as `forwardExtra(...)`, `addRewardToken(...)`, or another controlled mechanism that can route unexpecte"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(rewardTokens|extraRewards|additionalRewards|bonusTokens)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(harvest|collectRewards|claimRewards|sweepRewards|_claim)'}, {'function.body_contains_regex': 'for\\s*\\([^)]*rewardTokens?\\s*\\.length|rewardTokens?\\s*\\[\\s*i\\s*\\]'}, {'function.body_not_contains_regex': 'rescueTokens|forwardExtra|sweepExtra|addRewardToken|pendingExtraRewards|transferUnrecognized'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-reward-extra-tokens-unreachable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
