"""
slippage — generated from reference/patterns.dsl/slippage.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py slippage.yaml
Source: g1-002-detector-gap-slippage
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Slippage(AbstractDetector):
    ARGUMENT = "slippage"
    HELP = "Swap/trade entrypoint forwards a literal zero min-output value to a known AMM swap primitive, leaving the swap with no effective slippage floor."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/slippage.yaml"
    WIKI_TITLE = "Literal zero AMM min-output slippage floor"
    WIKI_DESCRIPTION = "A public or external mutating swap/trade-like function calls a known AMM swap primitive with a literal zero min-output argument, such as Uniswap V2 `amountOutMin = 0`, Uniswap V3 `amountOutMinimum: 0`, or Curve `min_dy = 0`, and does not enforce a visible post-swap minimum-output check."
    WIKI_EXPLOIT_SCENARIO = "A user calls a protocol entrypoint that forwards `amountOutMin = 0` to a router. A searcher sandwiches the transaction and moves the pool price so the protocol accepts an arbitrarily poor output amount."
    WIKI_RECOMMENDATION = "Require a caller-supplied nonzero min-output value, forward it to the AMM, and keep an explicit post-swap received-amount check where the router does not provide one. Reject zero min-output values at the entrypoint."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(router|swap|dex|uniswap|curve|amm|exchange)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)(swap|trade|buy|sell|harvest|rebalance|convert|zap|execute)'}, {'function.source_matches_regex': '(?is)(swapExact(?:TokensForTokens|ETHForTokens|TokensForETH|TokensForTokensSupportingFeeOnTransferTokens|ETHForTokensSupportingFeeOnTransferTokens|TokensForETHSupportingFeeOnTransferTokens)\\s*\\(\\s*[^,]+,\\s*0\\s*,|exactInput(?:Single)?\\s*\\([^;]*\\bamountOutMinimum\\s*:\\s*0\\b|exchange(?:_underlying)?\\s*\\(\\s*[^,]+,\\s*[^,]+,\\s*[^,]+,\\s*0\\s*\\))'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\([^;]*(amountOut|received|returned|outputAmount|dy)\\w*\\s*>=\\s*\\w*(min|minimum|expected)|check[_s]?lippage|slippageCheck|_validateSlippage)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — slippage: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
