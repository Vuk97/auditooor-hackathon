"""
staking-claim-immediate-roi-no-cooldown-stake — generated from reference/patterns.dsl/staking-claim-immediate-roi-no-cooldown-stake.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py staking-claim-immediate-roi-no-cooldown-stake.yaml
Source: defimon-deep-mine/Ethan_ETN_2026-01-08_post-2451 ($5.77K) + JFIN_2024-12-24_post-2465-context
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StakingClaimImmediateRoiNoCooldownStake(AbstractDetector):
    ARGUMENT = "staking-claim-immediate-roi-no-cooldown-stake"
    HELP = "Staking contract pays a stake-proportional ROI on the first claim with no minimum-stake duration gate. An attacker can flash-loan principal, stake, claim ROI, then unstake in a single transaction, draining the reward pool without holding stake."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/staking-claim-immediate-roi-no-cooldown-stake.yaml"
    WIKI_TITLE = "Staking ROI claim missing minimum-stake duration gate"
    WIKI_DESCRIPTION = "Staking pools that compute reward as `pending = staked * APR / divisor` and pay it out on `claim()` MUST gate the payout on a minimum elapsed-time since the user's most-recent stake. Without that gate, the formula yields a positive amount the moment a deposit lands, so a fresh deposit followed by an immediate claim collects yield that was meant to compensate long-duration stakers. The attacker rep"
    WIKI_EXPLOIT_SCENARIO = "Pool advertises 1% daily ROI on staked TOKEN. Attacker flash-loans 1,000,000 TOKEN, calls stake(1_000_000), then claimRoi() which credits 10,000 TOKEN as the day's payout, then unstake(1_000_000), repays the flash loan, and walks with 10,000 TOKEN — all in one block. Repeating across the day drains the reward budget. Real incident: Ethan ETN staking, BSC, 2026-01-08 (post-2451), reward calculation"
    WIKI_RECOMMENDATION = "Record `stakedAt[user] = block.timestamp` (or `stakeBlock[user] = block.number`) on every deposit. In the claim path, require `block.timestamp >= stakedAt[user] + MIN_STAKE_DURATION` (typical: ≥ 1 epoch) before computing pending. Update `stakedAt` to `block.timestamp` (the LAST stake wins) when a us"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(stake|deposit)|(claim[A-Z]|getReward|harvest)'}, {'contract.has_function_matching': '(?i)(stake|deposit)'}, {'contract.has_function_matching': '(?i)(claim|getReward|harvestReward|claimRoi|claimROI|claimReward)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(claim|getReward|harvest|claimReward|claimRoi|claimROI|claimDailyROI)$'}, {'function.body_contains_regex': '(?i)(\\bstaked\\b|stakeAmount|stakedAmount|userStake|stakingBalance|deposited|principal)\\s*\\*\\s*\\w+\\s*/'}, {'function.body_not_contains_regex': '(block\\.timestamp|now)\\s*[-+]\\s*(stakedAt|stakedSince|stakeBlock|lastStake|depositedAt|lockUntil|cooldownEnd)|require\\s*\\([^)]*lockDuration|require\\s*\\([^)]*minStake|require\\s*\\([^)]*stakeDuration|cooldown\\s*<=\\s*block\\.timestamp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — staking-claim-immediate-roi-no-cooldown-stake: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
