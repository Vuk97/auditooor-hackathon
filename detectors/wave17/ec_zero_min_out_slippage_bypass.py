"""
ec-zero-min-out-slippage-bypass — generated from reference/patterns.dsl/ec-zero-min-out-slippage-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-zero-min-out-slippage-bypass.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcZeroMinOutSlippageBypass(AbstractDetector):
    ARGUMENT = "ec-zero-min-out-slippage-bypass"
    HELP = "Swap function accepts user-supplied minAmountOut but does not enforce it is nonzero; passing minOut=0 fully disables slippage protection."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-zero-min-out-slippage-bypass.yaml"
    WIKI_TITLE = "Zero minAmountOut accepted — slippage bypass via user-supplied zero"
    WIKI_DESCRIPTION = "The function accepts a minAmountOut (or minOut, amountOutMin) parameter and passes it to an underlying AMM or aggregator without checking it is greater than zero. A user or contract calling with minOut=0 receives no slippage protection, allowing a sandwich attacker to move the price to the worst possible tick before the swap executes."
    WIKI_EXPLOIT_SCENARIO = "Protocol's swap() forwards user-supplied minOut to UniswapV3Router.exactInputSingle(). Contract caller passes minOut=0 in a multi-step tx. Sandwich bot sees pending tx, front-runs to move price 99% against user, user's swap executes at 1% of fair value, bot back-runs to profit."
    WIKI_RECOMMENDATION = "Enforce `require(minAmountOut > 0, 'no slippage protection')`. Alternatively, compute a minimum from a TWAP oracle: `uint256 minOut = twapPrice * amountIn * (10000 - maxSlippageBps) / 10000` and reject user values below this floor. Never forward a user-supplied zero to an AMM."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'minOut|minAmountOut|amountOutMin|minReturn|minReceived'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_name_matching': 'minOut|minAmountOut|amountOutMin|minReturn|minReceived|_minOut'}, {'function.body_contains_regex': 'swap|exactInput|exactOutput|swapExactTokens|exchange'}, {'function.body_not_contains_regex': 'require\\s*\\(.*min[Oo]ut\\s*>\\s*0|require\\s*\\(.*min.*>\\s*0|minOut\\s*!=\\s*0|assert.*minOut'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-zero-min-out-slippage-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
