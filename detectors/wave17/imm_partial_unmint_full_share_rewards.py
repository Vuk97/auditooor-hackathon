"""
imm-partial-unmint-full-share-rewards — generated from reference/patterns.dsl/imm-partial-unmint-full-share-rewards.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-partial-unmint-full-share-rewards.yaml
Source: immunefi/pods-finance-unmintwithrewards
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmPartialUnmintFullShareRewards(AbstractDetector):
    ARGUMENT = "imm-partial-unmint-full-share-rewards"
    HELP = "Partial-exit entrypoint pays rewards based on the caller's FULL share instead of the fraction being redeemed this call. Attacker repeatedly redeems dust amounts while claiming full-position rewards every time."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-partial-unmint-full-share-rewards.yaml"
    WIKI_TITLE = "Partial unmint / withdraw pays rewards on whole position (Pods Finance pattern)"
    WIKI_DESCRIPTION = "Many options / vesting / reward pools track a per-user `shares` balance that represents their stake in a reward pool, and a `mintedOptions[user]` that tracks how much of the underlying operational position the user currently holds. A reward-claim on a partial exit must scale the payout by the fraction being closed: `reward = shares[user] * (amount / mintedOptions[user]) * _rewardBalance() / totalS"
    WIKI_EXPLOIT_SCENARIO = "Pods Finance unmintWithRewards (Jun 2021): user with 100 options and rewardBalance 10 ETH calls `unmintWithRewards(1)`. The function computes `rewardsToSend = shares[user] * rewardBalance / totalShares` → ~10 ETH (their full share of rewards, because their share-count represents all 100 options). Caller pockets 10 ETH for burning 1/100th of their position, then repeats across 99 more calls and col"
    WIKI_RECOMMENDATION = "Any partial-exit reward path must scale by the redemption fraction: `reward = shares[user] * amountBeingRedeemed / mintedOptions[user] * rewardBalance / totalShares`. Use `Math.mulDiv` to avoid intermediate overflow. Add an invariant test: after any sequence of partial withdrawals, `sum(rewardsPaid)"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'unmint|withdrawRewards|claimRewards|_rewardBalance|mintedOptions'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(unmintWithRewards|withdrawRewards|claimRewards|redeemWithRewards|_unmintRewards)$'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': 'shares\\s*\\[\\s*msg\\.sender\\s*\\]\\s*(\\.mul|\\*)\\s*[^;]*rewardBalance'}, {'function.body_not_contains_regex': 'amountOfOptions\\s*(\\.mul|\\*|\\.div)|amount\\s*\\.\\s*mul\\s*\\([^)]*mintedOptions|amount\\s*\\*\\s*[^;]*mintedOptions|fractionRedeemed|_pendingScaled'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-partial-unmint-full-share-rewards: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
