"""
staking-reward-missing-checkpoint-on-transfer — generated from reference/patterns.dsl/staking-reward-missing-checkpoint-on-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py staking-reward-missing-checkpoint-on-transfer.yaml
Source: defihacklabs/PRXVT_2026-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StakingRewardMissingCheckpointOnTransfer(AbstractDetector):
    ARGUMENT = "staking-reward-missing-checkpoint-on-transfer"
    HELP = "Transferable reward-share token moves balances without checkpointing the reward index on sender and receiver. The receiver inherits zero `userRewardPerTokenPaid`, so `earned(to)` equals `balance * rewardPerToken` — a free claim for any newly-funded contract (PRXVT stPRXVT, January 2026, 32.8 ETH dra"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/staking-reward-missing-checkpoint-on-transfer.yaml"
    WIKI_TITLE = "Reward-share token ERC20 transfer missing reward checkpoint on from/to"
    WIKI_DESCRIPTION = "Synthetix-style reward distributors use a two-field accounting: `rewardPerTokenStored` (global accumulator) and `userRewardPerTokenPaid[user]` (last-seen snapshot). `earned(user) = balanceOf(user) * (rewardPerToken() - userRewardPerTokenPaid[user])`. If the share token itself is ERC20-transferable AND the `_transfer` / `_update` hook does not invoke the `updateReward(from); updateReward(to)` check"
    WIKI_EXPLOIT_SCENARIO = "PRXVT: attacker stakes PRXVT once to obtain stPRXVT, then in a loop (a) deploys a fresh `Attack2` contract via CREATE2, (b) transfers all stPRXVT to it, (c) has it call `stPRXVT.claimReward()` — which internally reads `earned(Attack2) = stBal * rewardPerToken()` because `userRewardPerTokenPaid[Attack2] == 0`. Each iteration pays the full accrued reward to the freshly-funded recipient. The attacker"
    WIKI_RECOMMENDATION = "Invoke the reward checkpoint on BOTH `from` and `to` inside the ERC20 transfer hook. In Synthetix-lineage code this is the `updateReward(from)` + `updateReward(to)` modifier call from `_beforeTokenTransfer`. Equivalently, set `userRewardPerTokenPaid[to] = rewardPerTokenStored` during the receiver's "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(userRewardPerTokenPaid|rewardPaid|rewardDebt|_rewardDebt)'}, {'contract.has_state_var_matching': '(balances|_balances|stakedBalance)'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '^(_transfer|_update|transfer|transferFrom)$'}, {'function.writes_storage_matching': '(balances|_balances|stakedBalance)'}, {'function.body_not_contains_regex': '(updateReward|_updateReward|_accrueReward|_accrue|_harvest|checkpoint|_checkpoint|updatePool|_updatePool)\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — staking-reward-missing-checkpoint-on-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
