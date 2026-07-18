"""
perp-half-liquidation-degrades-to-full-liquidation-atomically — generated from reference/patterns.dsl/perp-half-liquidation-degrades-to-full-liquidation-atomically.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-half-liquidation-degrades-to-full-liquidation-atomically.yaml
Source: auditooor-R75-c4-2023-03-polynomial-H70
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpHalfLiquidationDegradesToFullLiquidationAtomically(AbstractDetector):
    ARGUMENT = "perp-half-liquidation-degrades-to-full-liquidation-atomically"
    HELP = "The half-liquidation guard checks the pre-liquidation `safetyRatio` only. After a half-liquidation, the liquidation bonus pulls collateral out, dropping the ratio below the wipeout cutoff. A follow-up tx liquidates the rest in the same block — the user-protective band is effectively non-existent."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-half-liquidation-degrades-to-full-liquidation-atomically.yaml"
    WIKI_TITLE = "Partial-liquidation tier collapses to full liquidation in two atomic transactions due to liq-bonus drag"
    WIKI_DESCRIPTION = "Protocols often tier liquidation to be merciful at the boundary: `safetyRatio > 1` safe, `0.95 < r <= 1` half-liquidatable, `r <= 0.95` fully liquidatable ('wipeout'). The bug: half-liquidation's liquidation bonus removes (say) 10% extra collateral, so the post-half safetyRatio isn't at the same level — it drops sharply. A position starting right at r=1 can end up at r=0.9 after a half-liquidation"
    WIKI_EXPLOIT_SCENARIO = "(1) Bob's short has collateralRatio = 1.3e18 exactly — on the edge. maxLiquidatableDebt returns shortAmount/2 (half liquidation). (2) Liquidator Alice calls `liquidate(bob, shortAmount/2)`. Alice pays half the debt, receives 0.5 × shortValue × (1 + liqBonus) = 0.55 × shortValue in collateral. (3) Post-liquidation, Bob has 0.5×debt left and 1 - 0.55/original × originalCollateral remaining; safetyRa"
    WIKI_RECOMMENDATION = "Account for the liquidation bonus in the tier calculation: compute post-liquidation safetyRatio AFTER applying the bonus, and only allow a size such that the post ratio stays above WIPEOUT. Concretely: `safeHalfSize = largest s such that (collateral - s*(1+liqBonus)*price) / ((size - s) * markPrice "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(maxLiquidatableDebt|safetyRatio|liqRatio|liqBonus|WIPEOUT|halfLiquidation)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.state_mutability': 'view'}, {'function.name_matches': '(maxLiquidatableDebt|_maxLiquidatableDebt|computeMaxLiquidatable|partialLiquidationLimit)'}, {'function.body_contains_regex': 'safetyRatio|collateralRatio|healthRatio'}, {'function.body_contains_regex': '(return\\s+position\\.shortAmount\\s*/\\s*2|maxDebt\\s*=\\s*[^;]*/\\s*2|halfSize|size\\s*/\\s*2)'}, {'function.body_contains_regex': 'WIPEOUT|wipeout|fullLiquidation'}, {'function.body_not_contains_regex': '(safetyRatioAfterBonus|simulateHalfLiquidation|postLiquidationRatio|healthAfter)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-half-liquidation-degrades-to-full-liquidation-atomically: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
