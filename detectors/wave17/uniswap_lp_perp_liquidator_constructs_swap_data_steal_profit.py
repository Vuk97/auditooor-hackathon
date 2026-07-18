"""
uniswap-lp-perp-liquidator-constructs-swap-data-steal-profit — generated from reference/patterns.dsl/uniswap-lp-perp-liquidator-constructs-swap-data-steal-profit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uniswap-lp-perp-liquidator-constructs-swap-data-steal-profit.yaml
Source: auditooor-R75-c4-2023-12-particle-H26
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniswapLpPerpLiquidatorConstructsSwapDataStealProfit(AbstractDetector):
    ARGUMENT = "uniswap-lp-perp-liquidator-constructs-swap-data-steal-profit"
    HELP = "Liquidation call lets the liquidator supply arbitrary `data` specifying the swap route & pool; only the output-after-swap-covers-debt check is enforced. Liquidator routes through a pool/token they control, returns the minimum required, and keeps the spread between real market price and the minimum —"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uniswap-lp-perp-liquidator-constructs-swap-data-steal-profit.yaml"
    WIKI_TITLE = "Liquidation swap route is caller-controlled; only min-output check — liquidator steals borrower surplus"
    WIKI_DESCRIPTION = "Liquidation of a leveraged-LP or perp position often must swap the closed-position proceeds back into the debt token (e.g. the collateral is USDC-ETH and the debt is USDC). Delegating the swap to a caller-supplied `data` blob with only `amountReceived >= debt` as the post-condition is a classic trust-on-inputs bug: the attacker can build a 'pool' that accepts anything and returns the minimum. If t"
    WIKI_EXPLOIT_SCENARIO = "(1) Borrower position: collateral+tokenPremium = 120 USDC-worth of WETH, debt = 100 USDC. Position becomes liquidatable. (2) Attacker deploys FakeWETH and FakePool(FakeWETH, USDC). The FakePool has hook: on `swap(FakeWETH→USDC)`, mint 100 USDC to ParticlePositionManager and keep the 120 real WETH sent in. (3) Attacker calls `liquidatePosition(posId, data)` where data routes the 120 WETH through Fa"
    WIKI_RECOMMENDATION = "Whitelist the swap router / pool to canonical addresses (Uniswap v3 router, 1inch, 0x). Either hardcode the path or require the caller to provide (poolAddress, path) and verify against an allow-list. Alternatively: execute the swap internally against the canonical Uniswap pool for the token pair of "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(liquidatePosition|_closePosition|ParticlePositionManager|LpLoan|genericSwap)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(liquidatePosition|_liquidatePosition|_closePosition|closeLien|settleViaSwap)'}, {'function.body_contains_regex': '(params\\.data|swapData|swapParams|bytes\\s+data)'}, {'function.body_contains_regex': 'Base\\.swap|_swap\\s*\\(|executeSwap|router\\.swap'}, {'function.body_not_contains_regex': '(validatePool|whitelistedRouter|ROUTER\\s*!=|require\\s*\\([^)]*pool\\s*==\\s*expectedPool|canonicalPool)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uniswap-lp-perp-liquidator-constructs-swap-data-steal-profit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
