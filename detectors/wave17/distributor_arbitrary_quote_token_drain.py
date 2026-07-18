"""
distributor-arbitrary-quote-token-drain — generated from reference/patterns.dsl/distributor-arbitrary-quote-token-drain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py distributor-arbitrary-quote-token-drain.yaml
Source: code4arena/slice_ac-GTE-Launchpad-H06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DistributorArbitraryQuoteTokenDrain(AbstractDetector):
    ARGUMENT = "distributor-arbitrary-quote-token-drain"
    HELP = "Reward distributor donate/notifyReward path accepts a user-chosen token address and credits the donation to the canonical reward bucket. Attacker donates a worthless token, then claims a proportional share of real rewards."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/distributor-arbitrary-quote-token-drain.yaml"
    WIKI_TITLE = "Distributor accepts arbitrary quote token in donate/reward-notify"
    WIKI_DESCRIPTION = "A distributor contract exposes `donate(token, amount)` or `notifyReward(token, amount)` that increments the protocol's rewardBucket by `amount` regardless of `token`'s identity. Because all holders share pro-rata against this single accumulator when they `claim`, an attacker who donates zero-value ERC20 is credited as if they had donated the canonical quote token."
    WIKI_EXPLOIT_SCENARIO = "Distributor holds 100k USDC as accrued reward. Attacker mints 100k FAKE_TOKEN to themselves and calls `donate(FAKE_TOKEN, 100k)`. Distributor's `rewardBucket += 100k` (no token-identity check). Attacker's pro-rata share, which was near-zero before, now claims half the USDC pot via the standard claim path."
    WIKI_RECOMMENDATION = "Hard-code the canonical reward token or validate `require(token == quoteToken)` / `require(allowedRewardToken[token])`. Maintain a separate bucket per token when multi-token rewards are intentional."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Distributor|Rewards|Staking|reward'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(donate|notifyReward|addRewards|depositReward)'}, {'function.has_param_of_type': 'address'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'IERC20\\s*\\(\\s*\\w*(token|asset|quote)\\w*\\s*\\)\\.(transferFrom|transfer)|safeTransferFrom\\s*\\(\\s*\\w*(token|asset|quote)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w*token\\w*\\s*==\\s*(quoteToken|REWARD_TOKEN|canonicalToken|\\w+\\.quoteToken)|allowedToken\\s*\\[\\s*\\w*token'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — distributor-arbitrary-quote-token-drain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
