"""
provide-liquidity-reward-from-spot-reserves-no-twap — generated from reference/patterns.dsl/provide-liquidity-reward-from-spot-reserves-no-twap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py provide-liquidity-reward-from-spot-reserves-no-twap.yaml
Source: defimon-eos-mine-r97/Gradient_2025-06-23_post-1340 (gradient.trade GradientMarketMakerPool)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ProvideLiquidityRewardFromSpotReservesNoTwap(AbstractDetector):
    ARGUMENT = "provide-liquidity-reward-from-spot-reserves-no-twap"
    HELP = "Deposit-side liquidity-provision entrypoint values the caller's reward / receipt by reading instantaneous getReserves() from an AMM pair. With no TWAP or cooldown, a flashloan-funded reserve skew lets the attacker enter at a manipulated ratio and exit in the same tx via the matching withdraw path."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/provide-liquidity-reward-from-spot-reserves-no-twap.yaml"
    WIKI_TITLE = "Provide-liquidity entrypoint computes reward from spot reserves with no TWAP / cooldown"
    WIKI_DESCRIPTION = "AMM-style pools that pay a reward (or mint a receipt token) at deposit time MUST NOT compute the reward from instantaneous `getReserves()`. Within a single block an attacker can flashloan one side of the pair, swap to skew reserves, deposit at the manipulated ratio (collecting an oversized reward), withdraw in the same tx, swap back to normalise the pool, and repay the flashloan — netting the atta"
    WIKI_EXPLOIT_SCENARIO = "Gradient.trade GradientMarketMakerPool (June 2025). Attacker flashloaned WETH, swapped WETH→GRAY in the same pool to deplete the GRAY reserve and inflate WETH-per-GRAY price, then called provideLiquidity(GRAY) which credited rewards proportional to `weth_reserve * deposit / gray_reserve`. The withdraw path returned principal, the attacker swapped GRAY→WETH to undo the skew, repaid the flashloan, a"
    WIKI_RECOMMENDATION = "Compute deposit-side rewards from a TWAP (Uniswap V2 cumulative price over ≥10 minutes, V3 `observe()` over a 30-minute window) or a Chainlink feed. Alternatively, gate reward accrual on a per-account `lastDepositAt` timestamp + minimum-hold duration before the receipt is redeemable, so a same-tx pr"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)getReserves|IUniswapV2Pair|IPancakePair'}, {'contract.has_function_matching': '(?i)(provideLiquidity|addLiquidity|deposit|stake)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(provideLiquidity|addLiquidity|provide|depositLiquidity|stakeLiquidity|enter|joinPool)$'}, {'function.body_contains_regex': '(?i)getReserves\\s*\\(\\s*\\)|reserve0\\s*[*/]|reserve1\\s*[*/]|IUniswapV2Pair\\(.*\\)\\.getReserves|IPair\\(.*\\)\\.getReserves'}, {'function.body_contains_regex': '(?i)(reward|share|receipt|credit|points|rebate|earned)\\s*[+:=]|_mint\\s*\\(\\s*msg\\.sender|_balances\\[msg\\.sender\\]\\s*\\+='}, {'function.body_not_contains_regex': '(?i)observe\\s*\\(|consult\\(|cumulativePrice|twap|TWAP|chainlink|AggregatorV3|lastUpdate|cooldown|minDeposit|stakedAt|MIN_HOLD'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — provide-liquidity-reward-from-spot-reserves-no-twap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
