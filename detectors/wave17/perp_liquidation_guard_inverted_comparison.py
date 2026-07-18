"""
perp-liquidation-guard-inverted-comparison — generated from reference/patterns.dsl/perp-liquidation-guard-inverted-comparison.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-liquidation-guard-inverted-comparison.yaml
Source: auditooor-R73-fixdiff-mined-mux-aggregator-a91bc63bfb
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpLiquidationGuardInvertedComparison(AbstractDetector):
    ARGUMENT = "perp-liquidation-guard-inverted-comparison"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: a perp liquidation guard uses `require(getMarginRate(...) >= maintenanceMarginRate(...), \"MarginUnsafe\")`, permitting liquidation of healthy positions while blocking genuinely unsafe ones."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-liquidation-guard-inverted-comparison.yaml"
    WIKI_TITLE = "Liquidation guard compares margin rate with wrong direction (>= / > instead of <)"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Perp liquidation functions must allow execution only when the position is below maintenance margin. A guard like `require(getMarginRate(...) >= maintenanceMarginRate(...), \"MarginUnsafe\")` inverts the intended check: it permits liquidation when the position is safe and reverts on actually unsafe positions. The bug is visible only if you re"
    WIKI_EXPLOIT_SCENARIO = "Fixture-smoke/source-shape proof only. A keeper or attacker targets a healthy account whose margin rate sits above maintenance margin. The inverted guard passes, the protocol force-closes a solvent position, and the victim pays liquidation costs. At the same time, genuinely underwater positions fail the guard and cannot be liquidated, allowing bad debt to accumulate."
    WIKI_RECOMMENDATION = "Use the canonical unsafe-case check `require(marginRate < maintenanceMargin, \"MarginSafe\")` (or an equivalent health-factor comparison) so healthy positions revert and underwater positions succeed. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(liquidate|LiquidationCall|placeLiquidate|LiquidateOrder)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(liquidate|_liquidate|placeLiquidate|liquidationCall|liquidatePosition)'}, {'function.body_contains_regex': '(getMarginRate|marginRatio|healthFactor|collateralRatio|mmr|maintenanceMarginRate)'}, {'function.body_contains_regex': 'require\\s*\\([^;]*(getMarginRate|marginRatio|healthFactor|collateralRatio)[^;]*(>=|>)\\s*[^;]*(maintenance|mmr|liqThreshold)[^;]*\\)'}, {'function.body_not_contains_regex': 'require\\s*\\([^;]*(getMarginRate|marginRatio|healthFactor|collateralRatio)[^;]*<\\s*[^;]*(maintenance|mmr|liqThreshold)[^;]*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-liquidation-guard-inverted-comparison: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
