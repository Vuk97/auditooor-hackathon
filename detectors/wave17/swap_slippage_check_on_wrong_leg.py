"""
swap-slippage-check-on-wrong-leg — generated from reference/patterns.dsl/swap-slippage-check-on-wrong-leg.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py swap-slippage-check-on-wrong-leg.yaml
Source: auditooor-R73-code4rena-2024-08-superposition-35
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SwapSlippageCheckOnWrongLeg(AbstractDetector):
    ARGUMENT = "swap-slippage-check-on-wrong-leg"
    HELP = "swapOut-style wrappers decode (amount0, amount1) from inner swap but check slippage against the wrong index."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/swap-slippage-check-on-wrong-leg.yaml"
    WIKI_TITLE = "Slippage check compares minOut against the input-leg of an AMM swap return"
    WIKI_DESCRIPTION = "AMM wrappers that call an inner `swap()` returning `(amount0, amount1)` — where the in/out token ordering depends on zero-for-one — must map the tuple to the correct semantic slot before enforcing `minOut`. A swapOut wrapper that blindly takes `amountOut := abi.decode(...).1` and checks it is the ASSERTED output will actually be checking the input token amount; the user's slippage guard is on the "
    WIKI_EXPLOIT_SCENARIO = "User swaps 1000 USDC expecting ≥ 0.3 ETH. Wrapper calls inner swap(token, false, 1000, MAX). Inner returns (amount0=-0.001 ETH, amount1=1000 USDC). Wrapper names the second element `swapAmountOut` and checks `1000 >= minOut(0.3e18)` — passes. User receives 0.001 ETH instead of 0.3 ETH."
    WIKI_RECOMMENDATION = "Name variables unambiguously (`amountToken0`, `amountToken1`) and write an explicit mapping line: `uint256 outAmount = zeroForOne ? amount1 : amount0;`. Check `outAmount >= minOut` (using the token's actual expected sign). Add a test that routes through both directions and asserts slippage reverts w"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)swap(Out|In|Exact)[A-Za-z0-9]*'}, {'function.body_contains_regex': '(?i)require\\s*\\(\\s*(swapAmountOut|amountOut|outAmt)\\s*>=\\s*(minOut|amountOutMin|int256\\(minOut\\))'}, {'function.body_contains_regex': '(?i)abi\\.decode\\(\\s*\\w+\\s*,\\s*\\(\\s*int256\\s*,\\s*int256\\s*\\)\\s*\\)'}, {'function.has_external_call': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — swap-slippage-check-on-wrong-leg: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
