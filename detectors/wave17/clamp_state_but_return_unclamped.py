"""
clamp-state-but-return-unclamped — generated from reference/patterns.dsl/clamp-state-but-return-unclamped.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py clamp-state-but-return-unclamped.yaml
Source: auditooor-R65-centrifuge-Holdings.decrease
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ClampStateButReturnUnclamped(AbstractDetector):
    ARGUMENT = "clamp-state-but-return-unclamped"
    HELP = "Decrement function clamps its storage slot to zero on underflow but returns the unclamped computed value. If the caller forwards that return to a second accounting system (ledger post, NAV manager, share price computation), the two books desync permanently — the downstream ledger records more value "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/clamp-state-but-return-unclamped.yaml"
    WIKI_TITLE = "Clamp-state but return-unclamped — accounting desync on decrement"
    WIKI_DESCRIPTION = "A state-decrement function uses the saturating `amount > state ? 0 : state - amount` idiom to avoid reverting on underflow, but its `returns (uint128 amountValueUnclamped)` exposes the full pre-clamp computation. Upstream callers assign that return to a variable that is then posted to a parallel accounting ledger (`accounting.post(Equity, Asset, value)` / `_postAccounting(diff)` etc.). Because the"
    WIKI_EXPLOIT_SCENARIO = "A hub-spoke protocol stores per-pool holdings. `Holdings.decrease(pool, amount, price)` computes `unclampedValue = amount * price` and saturates the storage `assetAmountValue` to zero on underflow. It returns unclamped value. The spoke-originated redemption handler forwards that return to `Accounting.updateValue(..., false, value)` which posts `DR Equity value, CR Asset value`. On a redemption exe"
    WIKI_RECOMMENDATION = "Return the clamped (actually-removed) value, not the unclamped conversion. Keep the original unclamped amount only for event emission:\n\n```solidity\nfunction decrease(…)\n    external\n-   returns (uint128 amountValueUnclamped)\n+   returns (uint128 amountValueBooked)\n{\n-   amountValueUnclamped "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\?\\s*0\\s*:\\s*[a-zA-Z_][a-zA-Z0-9_.]*\\s*-\\s*[a-zA-Z_]'}, {'function.body_contains_regex': 'returns\\s*\\(\\s*(uint128|uint256|int128|int256)\\s+(amountValueUnclamped|unclampedAmount|rawAmount|rawValue|computedValue|valueUnclamped|amountUnclamped)'}, {'function.body_not_contains_regex': '(amountBooked|clampedAmount|actualDecrement|actualWithdrawn)\\s*='}, {'function.name_matches': 'decrease|withdraw|decrement|burn|reduce|subAmount|takeOut|unstake'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — clamp-state-but-return-unclamped: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
