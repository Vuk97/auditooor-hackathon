"""
rs-rewards-duplicate-pair-key-missing-pool-identity - generated from reference/patterns.dsl/rs-rewards-duplicate-pair-key-missing-pool-identity.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rs-rewards-duplicate-pair-key-missing-pool-identity.yaml
Source: fire4-rwrq-rewards-distribution-skew-8542fded6d21
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RsRewardsDuplicatePairKeyMissingPoolIdentity(AbstractDetector):
    ARGUMENT = "rs-rewards-duplicate-pair-key-missing-pool-identity"
    HELP = "Listed-token reward accounting is keyed only by token pair, not canonical pool identity."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rs-rewards-duplicate-pair-key-missing-pool-identity.yaml"
    WIKI_TITLE = "Reward key omits canonical pool identity"
    WIKI_DESCRIPTION = "Reward hooks for pool systems must bind rewards to the canonical pool identity. If rewards are keyed only by (token0, token1) while pool identity also includes fee, tick spacing, hooks, or a pool id, an attacker can create a lookalike pool for the same listed pair and claim rewards intended for the canonical pool."
    WIKI_EXPLOIT_SCENARIO = "A legitimate pool for token A and token B receives rewards. The reward hook stores rewards under hash(A, B). An attacker creates a second pool with token A and token B but different fee, tick spacing, or hooks. Because claimRewards recomputes only hash(A, B), the lookalike pool can claim the same reward stream."
    WIKI_RECOMMENDATION = "Key reward balances by canonical pool id or full PoolKey, and require the supplied pool key to match the registered canonical pool for the token pair before distributing or claiming rewards."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(reward|rewards|emission|incentive)'}, {'contract.source_matches_regex': '(?i)(PoolKey|token0|token1)'}, {'contract.source_matches_regex': '(?i)(fee|tickSpacing|hooks|poolId|canonicalPool|registeredPool)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(distributeRewards|emitRewards|creditRewardsForPool|rewardForPair|updateRewardStream|recordReward|accumulateReward|claimPoolReward|claimRewards)'}, {'function.source_matches_regex': '(?i)(token0\\s*,\\s*token1|key\\.token0\\s*,\\s*key\\.token1|abi\\.encode(?:Packed)?\\s*\\([^;]*(token0|key\\.token0)[^;]*(token1|key\\.token1))'}, {'function.source_matches_regex': '(?i)(rewards?ByPair|rewards?PerPair|pairRewards|rewardPair|pairReward|rewards?\\s*\\[\\s*pair\\s*\\])'}, {'function.not_source_matches_regex': '(?i)(key\\.fee|key\\.tickSpacing|key\\.hooks|canonicalPool|registeredPool|whitelistedPool|poolId|PoolId|isCanonicalPool|canonicalPoolForPair)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - rs-rewards-duplicate-pair-key-missing-pool-identity: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
