"""
reward-mint-uses-spot-pool-ratio-no-flashloan-guard — generated from reference/patterns.dsl/reward-mint-uses-spot-pool-ratio-no-flashloan-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-mint-uses-spot-pool-ratio-no-flashloan-guard.yaml
Source: auditooor-R76-rekt-pancakebunny-2021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardMintUsesSpotPoolRatioNoFlashloanGuard(AbstractDetector):
    ARGUMENT = "reward-mint-uses-spot-pool-ratio-no-flashloan-guard"
    HELP = "Reward minting reads spot reserves from a Uniswap-V2-style pair to value the user's claim. No TWAP / no flash-loan cooldown means a single-block pool imbalance mints arbitrary tokens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-mint-uses-spot-pool-ratio-no-flashloan-guard.yaml"
    WIKI_TITLE = "Reward mint values user claim from instantaneous AMM reserves with no TWAP or cooldown"
    WIKI_DESCRIPTION = "Yield-farm vaults often mint their native token as a reward proportional to the harvested pool's USD value. If that USD value is computed by reading `IPair.getReserves()` inside the mint function, a flash-loan-funded swap can push the pool ratio into a state where the reward is valued 100x too high, minting massive amounts of the native token to the attacker. PancakeBunny lost ~$45M in May 2021 (p"
    WIKI_EXPLOIT_SCENARIO = "Attacker flash-loans 3.7M WBNB + 2.96M USDT. Deposits WBNB and USDT into the WBNB-BUSDT PCS pool, then swaps large amounts to push the WBNB-BUNNY pool's BUNNY reserve toward zero (so BUNNY-per-BNB price explodes). Calls `Vault.getReward()` which prices the harvested LP via the manipulated BUNNY-BNB pool, reporting the harvest as worth $1B. Contract mints 697k BUNNY to attacker. Attacker dumps BUNN"
    WIKI_RECOMMENDATION = "Never use `getReserves()` as a price source for mint / reward valuation. Use a TWAP (Uniswap V2's `currentCumulativePrices` over ≥10 min, or Uniswap V3's `observe()` with a 30-min window) or a Chainlink aggregator. Add a per-account cooldown between deposit and harvest to ensure the attacker's flash"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Protocol mints or values user claim / reward using `IPair.getReserves()` or `IERC20.balanceOf(pair)` as the price source.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)getReward|harvest|mintRewards|claimReward|claim$|compound'}, {'function.body_contains_regex': '(?i)IPancakePair|IUniswapV2Pair|getReserves\\s*\\(\\s*\\)|reserve0\\s*\\*|reserve1\\s*\\*'}, {'function.body_not_contains_regex': '(?i)observe\\s*\\(|consult\\(|twap|cumulativePrice|chainlink|AggregatorV3|lastUpdatedAt|cooldown'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reward-mint-uses-spot-pool-ratio-no-flashloan-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
