"""
non-user-controlled-swap-bound-inspector — generated from reference/patterns.dsl/non-user-controlled-swap-bound-inspector.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py non-user-controlled-swap-bound-inspector.yaml
Source: auditooor-known-limitation-burndown
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NonUserControlledSwapBoundInspector(AbstractDetector):
    ARGUMENT = "non-user-controlled-swap-bound-inspector"
    HELP = "Externally callable swap wrapper computes a router min/max bound internally instead of accepting a user-supplied bound."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/non-user-controlled-swap-bound-inspector.yaml"
    WIKI_TITLE = "Non-user-controlled swap boundary amount"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row flags a narrow Solidity shape where a public/external swap wrapper computes a `protocolMinOut`/similar value from a quote, oracle, slippage policy, or arithmetic expression and passes it as `amountOutMinimum` while exposing no min/max/slippage parameter to the caller. This is NOT_SUBMIT_READY because internal bounds can be safe when based on a manipu"
    WIKI_EXPLOIT_SCENARIO = "A user calls a swap/rebalance wrapper that derives `protocolMinOut = quotedOut * (10000 - slippageBps) / 10000` and passes it as `amountOutMinimum`. If `quotedOut` or `slippageBps` is attacker-influenced or too permissive, the user cannot supply a tighter minimum and can receive worse execution than intended."
    WIKI_RECOMMENDATION = "For user-facing swaps, accept a caller-supplied minimum output/maximum input and pass that value through to the router. For protocol-managed swaps, document and prove that the internal bound source is manipulation-resistant and policy-controlled."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(swap|exactInputSingle|amountOutMinimum|minAmountOut|slippage)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(?i)\\.(exactInputSingle|exactInput|swapExactTokensForTokens|swap)\\s*\\('}, {'function.body_contains_regex': '(?i)\\b(amountOutMinimum|amountOutMin|minAmountOut|minOut|minReturn|maxAmountIn|amountInMaximum)\\b'}, {'function.body_contains_regex': '(?i)\\b(?:uint(?:256)?\\s+)?[A-Za-z_][A-Za-z0-9_]*(?:Min|Minimum|Bound|Limit|Slippage)[A-Za-z0-9_]*\\s*=\\s*[^;]*(quote|oracle|getAmount|preview|balanceOf|slippage|BPS|bps|[*/])[^;]*;'}, {'function.parameter_not_matches_regex': '(?i)(amountOutMinimum|amountOutMin|minAmountOut|minOut|minReturn|maxAmountIn|amountInMaximum|slippage|tolerance|bound)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — non-user-controlled-swap-bound-inspector: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
