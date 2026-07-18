"""
comet-rewards-reconfigure-silent-reset — generated from reference/patterns.dsl/comet-rewards-reconfigure-silent-reset.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-rewards-reconfigure-silent-reset.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-85e789819
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometRewardsReconfigureSilentReset(AbstractDetector):
    ARGUMENT = "comet-rewards-reconfigure-silent-reset"
    HELP = "Reward-config setter overwrites an existing configuration without an 'already configured' guard. A governance misstep or malicious proposal can silently swap the reward token mid-flight, orphaning accrued reward balances denominated in the old token and breaking user claims."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-rewards-reconfigure-silent-reset.yaml"
    WIKI_TITLE = "Reward-config setter allows silent reconfiguration of reward token"
    WIKI_DESCRIPTION = "A rewards distributor keyed on `comet` (or `pool`, `market`) stores per-market reward configuration in a mapping `rewardConfig[comet] = RewardConfig(token, accrualScale, ...)`. Users accrue claimable amounts denominated in `RewardConfig.token`. A setter that writes `rewardConfig[comet] = new RewardConfig(...)` without checking `rewardConfig[comet].token == address(0)` lets governance overwrite the"
    WIKI_EXPLOIT_SCENARIO = "Comet's `_setRewardConfig` originally had no check (ChainSecurity / OZ comment fixed in commit 85e789819). Steps: (1) governance proposal #1 configures comet X with reward token COMP; users accrue millions of COMP-denominated indices; (2) an adversarial proposal #2 calls `_setRewardConfig(X, attackerToken)`; the mapping entry is blindly overwritten, `accrualScale` is now based on `attackerToken.de"
    WIKI_RECOMMENDATION = "Add the sentinel: `if (rewardConfig[comet].token != address(0)) revert AlreadyConfigured(comet);`. Provide a separate explicit migration function (e.g. `migrateRewardToken(oldToken, newToken, conversionRate)`) that (a) forces a batch-accrue for all users, (b) swaps the token atomically with a conver"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'rewardConfig|RewardConfig|rewardToken|setRewardConfig|_setRewardConfig'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '^(setRewardConfig|_setRewardConfig|addRewardToken|configureReward|setReward|updateRewardToken)$'}, {'function.body_contains_regex': 'rewardConfig\\s*\\[\\s*\\w+\\s*\\]\\s*=|rewardToken\\s*=|RewardConfig\\s*\\('}, {'function.body_not_contains_regex': 'rewardConfig\\s*\\[\\s*\\w+\\s*\\]\\.token\\s*!=\\s*address\\(0\\)|AlreadyConfigured|alreadySet|already.*exist'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-rewards-reconfigure-silent-reset: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
