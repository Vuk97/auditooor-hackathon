"""
missing-deadline-param-on-swap-external — generated from reference/patterns.dsl/missing-deadline-param-on-swap-external.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-deadline-param-on-swap-external.yaml
Source: solodit/C0118
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingDeadlineParamOnSwapExternal(AbstractDetector):
    ARGUMENT = "missing-deadline-param-on-swap-external"
    HELP = "External/public swap or trade entrypoint has no deadline / expiry parameter and no deadline check anywhere in its body. Transactions can sit in the mempool indefinitely and execute at an adverse price minutes or hours later."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-deadline-param-on-swap-external.yaml"
    WIKI_TITLE = "Missing deadline parameter on external swap function"
    WIKI_DESCRIPTION = "A user-facing function named `swap`, `swapExactInput`, `swapExactOutput`, `trade`, `exchange`, `buyToken`, or `sellToken` accepts a uint256 quantity argument but contains no deadline or expiry token in its body. The caller has no way to bound how long the trade remains valid; validators and MEV searchers can delay the transaction's inclusion and execute it after the price window the user intended "
    WIKI_EXPLOIT_SCENARIO = "An AMM periphery exposes `swap(uint256 amountIn, uint256 minOut, address[] path)` with no deadline argument and no timestamp check in the body. A user's transaction is picked up in the mempool during a volatility spike but a validator withholds it for two blocks. By the time it lands the pool has moved such that the realised price is materially worse than the user expected, yet minOut still passes"
    WIKI_RECOMMENDATION = "Add a `uint256 deadline` parameter to every external swap/trade entrypoint and enforce `require(deadline >= block.timestamp, \"expired\")` before executing. Forward the same deadline verbatim into the underlying router call. Reject deadlines that are more than ~30 minutes beyond block.timestamp to p"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(swap|swapExactInput|swapExactOutput|trade|exchange|buyToken|sellToken)$'}, {'function.has_param_of_type': 'uint256'}, {'function.body_not_contains_regex': 'deadline|expiry|block\\.timestamp\\s*<=?\\s*\\w|validUntil'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — missing-deadline-param-on-swap-external: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
