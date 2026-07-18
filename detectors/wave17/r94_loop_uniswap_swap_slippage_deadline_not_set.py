"""
r94-loop-uniswap-swap-slippage-deadline-not-set — generated from reference/patterns.dsl/r94-loop-uniswap-swap-slippage-deadline-not-set.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-uniswap-swap-slippage-deadline-not-set.yaml
Source: solodit-19136-sherlock-ussd-autonomous-secure-dollar
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopUniswapSwapSlippageDeadlineNotSet(AbstractDetector):
    ARGUMENT = "r94-loop-uniswap-swap-slippage-deadline-not-set"
    HELP = "r94-loop-uniswap-swap-slippage-deadline-not-set"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-uniswap-swap-slippage-deadline-not-set.yaml"
    WIKI_TITLE = "r94-loop-uniswap-swap-slippage-deadline-not-set"
    WIKI_DESCRIPTION = "r94-loop-uniswap-swap-slippage-deadline-not-set"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-uniswap-swap-slippage-deadline-not-set"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Uniswap|Router|Swap|USSD|Rebalance|DEX)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(swap|rebalance|exactInput|executeSwap|uniswapSwap|tradeViaUniswap|routerExactInput)'}, {'function.source_matches_regex': '(swapExactTokensForTokens|exactInputSingle|ISwapRouter|IUniswapV2Router\\w*|router\\.swap)'}, {'function.source_matches_regex': '(amountOutMin(?:imum)?\\s*:\\s*0|,\\s*0\\s*,\\s*type\\(uint256\\)\\.max)'}, {'function.not_source_matches_regex': '(userMinOut|slippageBps|require\\s*\\(\\s*\\w*received\\s*>=|callerSuppliedDeadline|deadline\\s*:\\s*\\w*(user|caller))'}]

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
                info = [f, f" — r94-loop-uniswap-swap-slippage-deadline-not-set: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
