"""
fx-balancer-recovery-mode-wrong-limits — generated from reference/patterns.dsl/fx-balancer-recovery-mode-wrong-limits.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-balancer-recovery-mode-wrong-limits.yaml
Source: github:balancer/balancer-v3-monorepo@4034469
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxBalancerRecoveryModeWrongLimits(AbstractDetector):
    ARGUMENT = "fx-balancer-recovery-mode-wrong-limits"
    HELP = "Composite liquidity removal in recovery mode passes params.minAmountsOut (the outer token limits) to removeLiquidityRecovery() for the parent pool. These limits correspond to the final tokens out, not the parent pool tokens, causing incorrect slippage enforcement at the wrong level."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-balancer-recovery-mode-wrong-limits.yaml"
    WIKI_TITLE = "Composite remove-liquidity passes outer minAmountsOut to inner recovery — wrong slippage level"
    WIKI_DESCRIPTION = "Composite liquidity routers that handle pools-within-pools must apply slippage limits at the correct nesting level. In recovery mode, passing the outer-pool minAmountsOut (child/leaf token limits) to the parent pool's removeLiquidityRecovery enforces limits on BPT amounts rather than the actual output tokens, allowing the parent pool withdrawal to occur with no effective slippage protection."
    WIKI_EXPLOIT_SCENARIO = "Balancer CLR audit (2024): composite router passes params.minAmountsOut to parent pool's removeLiquidityRecovery. These are limits for final output tokens but are applied as limits for parent pool BPT amounts. A pool with unfavorable BPT rates can drain more value than the user's slippage tolerance allows."
    WIKI_RECOMMENDATION = "Pass `new uint256[](parentPoolTokens.length)` (zero limits) to removeLiquidityRecovery for the parent pool, and enforce the actual minAmountsOut at the end of the full composite operation after all nested unwrapping is complete."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^removeLiquidityRecovery$|^isPoolInRecoveryMode$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'removeLiquidity|removeLiquidityComposite|withdrawComposite'}, {'function.body_contains_regex': 'isPoolInRecoveryMode|RecoveryMode'}, {'function.body_contains_regex': 'removeLiquidityRecovery\\(.*params\\.minAmountsOut\\)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-balancer-recovery-mode-wrong-limits: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
