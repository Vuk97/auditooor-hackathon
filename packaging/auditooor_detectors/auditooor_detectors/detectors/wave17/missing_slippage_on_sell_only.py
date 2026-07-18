"""
missing-slippage-on-sell-only — generated from reference/patterns.dsl/missing-slippage-on-sell-only.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-slippage-on-sell-only.yaml
Source: solodit-cluster/C0244
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingSlippageOnSellOnly(AbstractDetector):
    ARGUMENT = "missing-slippage-on-sell-only"
    HELP = "Sell-side / exit-side function (sell, sellToken, exitPosition, closePosition, redeemForStable, _withdrawRewards, _sell, swapForETH/Stable) invokes a router or Curve swap without any minAmountOut / amountOutMin / minReceived guard — sandwich / MEV risk on the side the protocol forgot to protect."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-slippage-on-sell-only.yaml"
    WIKI_TITLE = "Missing slippage on sell / exit / withdraw side (asymmetric slippage protection)"
    WIKI_DESCRIPTION = "Protocols frequently enforce slippage protection on the buy / deposit / mint side of an AMM interaction and forget to apply the mirror guard on the sell / exit / withdraw side. This detector flags state-mutating public or external functions whose names place them on the sell surface (sell, sellToken, exitPosition, closePosition, redeemForStable, _withdrawRewards, _sell, swapForETH, swapForStable) "
    WIKI_EXPLOIT_SCENARIO = "Protocol's RewardReceiver contract exposes `_withdrawRewards()` which, when triggered by the keeper, sells accumulated reward tokens for the base asset via `router.swapExactTokensForTokens(balance, 0, path, address(this), block.timestamp)`. A sandwich bot monitors keeper transactions in the mempool, front-runs by pushing the reward token's price down, lets the withdraw execute at the depressed pri"
    WIKI_RECOMMENDATION = "Add an `amountOutMin` / `minReceived` parameter to every sell-side entrypoint and forward it to the router. For internal / keeper-triggered helpers (`_withdrawRewards`, `_sell`) read the minimum from storage (set by an off-chain oracle / TWAP with a tolerance band) rather than hardcoding zero. Rejec"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.name_matches': '^sell$|^sellToken$|^sellTokens$|^swapForETH$|^swapForStable$|^_sell$|^exitPosition$|^closePosition$|^redeemForStable$|^_withdrawRewards$'}, {'function.body_contains_regex': {'regex': 'router\\.swap|\\.swapExact|\\.swap\\s*\\(|pool\\.exchange|IUniswapV2Router|IUniswapV3SwapRouter|_doSwap'}}, {'function.body_not_contains_regex': 'amountOutMin|minAmountOut|require\\s*\\(\\s*[^;)]*received\\b[^;)]*>=\\s*[^;)]*(min|_min)|minReceived|_minOut|minOutputAmount'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — missing-slippage-on-sell-only: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
