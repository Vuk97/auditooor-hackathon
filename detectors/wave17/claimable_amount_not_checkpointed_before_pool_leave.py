"""
claimable-amount-not-checkpointed-before-pool-leave — generated from reference/patterns.dsl/claimable-amount-not-checkpointed-before-pool-leave.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py claimable-amount-not-checkpointed-before-pool-leave.yaml
Source: auditooor-known-limitation-burndown
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ClaimableAmountNotCheckpointedBeforePoolLeave(AbstractDetector):
    ARGUMENT = "claimable-amount-not-checkpointed-before-pool-leave"
    HELP = "Pool leave/exit path reduces a user's pool shares before checkpointing claimable rewards, so rewards accrued against the pre-exit balance are lost or under-accounted."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/claimable-amount-not-checkpointed-before-pool-leave.yaml"
    WIKI_TITLE = "Claimable amount not checkpointed before pool leave"
    WIKI_DESCRIPTION = "Reward-bearing pool contracts commonly derive `claimableAmount[user]` from the user's current pool shares and a global reward index. If `leavePool`, `exitPool`, `ragequit`, or a liquidity withdrawal mutates shares before settling the user's claimable amount, the later reward checkpoint sees the reduced balance and omits rewards earned before exit."
    WIKI_EXPLOIT_SCENARIO = "A user holds pool shares while rewards accrue. They call `leavePool`, which burns or subtracts the shares without first calling the reward checkpoint. When the user later claims, `claimableAmount[user]` is computed from the post-exit balance, leaving the pre-exit rewards stranded or redistributed."
    WIKI_RECOMMENDATION = "Call the per-user reward checkpoint before any pool leave, exit, ragequit, burn, or liquidity-removal mutation. Keep the checkpoint before share and total-supply writes, then proceed with the balance reduction."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(claimable|pendingReward|rewardDebt|rewardPerShare|rewardIntegral|lastCheckpoint|accrued)'}, {'contract.has_function_matching': '(?i)(leavePool|exitPool|ragequit|withdraw|removeLiquidity)'}, {'contract.source_matches_regex': '(?i)(checkpoint|updateReward|settleReward|claimable)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(leavePool|exitPool|leave|exit|ragequit|withdraw|withdrawLiquidity|removeLiquidity)'}, {'function.source_matches_regex': '(?i)(poolShares|totalPoolShares|lpBalance|memberShares|stakedBalance|balanceOf|_burn)\\s*(\\[|\\(|[-+*/]?=)'}, {'function.writes_storage_matching': '(?i)(poolShares|totalPoolShares|lpBalance|memberShares|stakedBalance|balance|supply|shares)'}, {'function.body_not_contains_regex': '(?i)(checkpoint|updateReward|settleReward|accrueReward|_updateRewards|_checkpointClaimable|claimableAmount\\s*\\[[^\\]]+\\]\\s*\\+=|pendingRewards\\s*\\[[^\\]]+\\]\\s*\\+=)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — claimable-amount-not-checkpointed-before-pool-leave: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
