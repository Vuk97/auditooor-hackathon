"""
liquidation-bad-debt-check-skipped-on-partial-close — generated from reference/patterns.dsl/liquidation-bad-debt-check-skipped-on-partial-close.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-bad-debt-check-skipped-on-partial-close.yaml
Source: auditooor-R75-c4-yield-2024-05-predy-189
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationBadDebtCheckSkippedOnPartialClose(AbstractDetector):
    ARGUMENT = "liquidation-bad-debt-check-skipped-on-partial-close"
    HELP = "Negative-margin compensation is only charged when position is fully closed; partial liquidations leaving negative margin dump loss on protocol."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-bad-debt-check-skipped-on-partial-close.yaml"
    WIKI_TITLE = "Partial liquidation skips bad-debt compensation, letting liquidator keep slippage profit"
    WIKI_DESCRIPTION = "Liquidation paths that reward the liquidator with trade slippage (`liquidator buys at oracle price, returns oracle × (1-slippage)`) typically require the liquidator to cover any residual negative margin so the protocol is never left with bad debt. A common bug gates the bad-debt-compensation transfer behind `hasPosition == false` — only after full close. Partial liquidations that intentionally lea"
    WIKI_EXPLOIT_SCENARIO = "Predy LiquidationLogic: liquidator liquidates 99.99% of a 1 ETH long. margin goes to -100 USDC. Because hasPosition is still true (0.0001 ETH left), the `if (!hasPosition) { if (remainingMargin < 0) transferFrom(msg.sender, ...) }` branch does not execute. The 100 USDC loss is absorbed by the pool. Liquidator kept the 4.75% slippage reward."
    WIKI_RECOMMENDATION = "Evaluate bad-debt compensation on every liquidation, not only on full close: `if (remainingMargin < 0) safeTransferFrom(msg.sender, self, -remainingMargin);`. Alternatively, require `hasPosition == false` as a strict post-condition of liquidation (no partial liquidations allowed)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(liquidate|executeLiquidate|closePositionForLiquidator)'}, {'function.body_contains_regex': '(?i)(hasPosition|positionAmount|amountBase)\\s*(==|!=)\\s*(0|false)'}, {'function.body_contains_regex': '(?i)(remainingMargin|vault\\.margin|marginAmount)\\s*<\\s*0'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)safeTransferFrom\\s*\\(\\s*(msg\\.sender|liquidator)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-bad-debt-check-skipped-on-partial-close: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
