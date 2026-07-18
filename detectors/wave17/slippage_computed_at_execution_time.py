"""
slippage-computed-at-execution-time — generated from reference/patterns.dsl/slippage-computed-at-execution-time.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py slippage-computed-at-execution-time.yaml
Source: code4arena/slice_ac-Virtuals-M-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SlippageComputedAtExecutionTime(AbstractDetector):
    ARGUMENT = "slippage-computed-at-execution-time"
    HELP = "Swap slippage bound (minAmountOut) is computed from live reserves / oracle read in the same tx as the swap. Sandwich reads the same manipulated reserves and satisfies the bound trivially — slippage protection is effectively zero."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/slippage-computed-at-execution-time.yaml"
    WIKI_TITLE = "Slippage bound computed at execution time from live reserves"
    WIKI_DESCRIPTION = "Functions that call swap with a minOut derived from getReserves() / balanceOf(address(this)) / getAmountOut within the same transaction offer no MEV protection: any attacker sandwiching this swap moves the reserves and then the computed bound is moved alongside, so require(amountOut >= bound) always passes. A caller-supplied (signed) bound is the only correct construction."
    WIKI_EXPLOIT_SCENARIO = "AgentTax.dcaSell computes `minOut = getAmountOut(in, reserveIn, reserveOut) * 995 / 1000` right before calling swap. Sandwicher frontruns with a large buy, moving the reserves; the victim's just-computed minOut is now consistent with the drained reserves, so the swap fills at a hugely degraded price. Sandwicher backruns for profit."
    WIKI_RECOMMENDATION = "Accept minAmountOut (or maxAmountIn) as an EIP-712-signed caller parameter with a deadline, or source the bound from a TWAP / Chainlink oracle averaged over multiple blocks. Never derive it from spot reserves in the same call."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'swap|Swap|Router|Pair|dcaSell'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'swapExactTokensForTokens\\s*\\(|swap\\s*\\([^)]*\\)|exactInputSingle\\s*\\(|exactInput\\s*\\('}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'getReserves\\s*\\(\\s*\\)|balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|getAmountOut\\s*\\(|latestAnswer\\s*\\(\\s*\\)|latestRoundData\\s*\\('}, {'function.body_not_contains_regex': '_minOut|minAmountOut\\s*[,)]|amountOutMin\\s*[,)]|sqrtPriceLimitX96\\s*='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — slippage-computed-at-execution-time: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
