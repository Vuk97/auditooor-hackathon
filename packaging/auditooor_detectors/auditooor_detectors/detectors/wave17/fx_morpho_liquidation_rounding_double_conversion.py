"""
fx-morpho-liquidation-rounding-double-conversion — generated from reference/patterns.dsl/fx-morpho-liquidation-rounding-double-conversion.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-morpho-liquidation-rounding-double-conversion.yaml
Source: github:morpho-org/morpho-blue@289ad5e
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxMorphoLiquidationRoundingDoubleConversion(AbstractDetector):
    ARGUMENT = "fx-morpho-liquidation-rounding-double-conversion"
    HELP = "Liquidation path computes repaidAssets before final share-to-asset rounding, accumulating two rounding errors that systematically favor the liquidator over the protocol."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-morpho-liquidation-rounding-double-conversion.yaml"
    WIKI_TITLE = "Liquidation rounding: repaidAssets computed before share round-trip accumulates double error"
    WIKI_DESCRIPTION = "In a two-branch liquidate() function, the repaidAssets intermediate variable is calculated using toAssetsUp on raw shares before those shares are rounded down via toSharesDown. The subsequent toAssetsUp pass on the rounded shares produces a different (higher) value, meaning repaidAssets overstates the actual debt repaid."
    WIKI_EXPLOIT_SCENARIO = "Morpho Blue pre-cantina fix (2023): liquidator supplies seizedAssets path. The intermediate repaidAssets is computed with toAssetsUp, then repaidShares is computed via toSharesDown on that value. A second toAssetsUp on repaidShares diverges from the original repaidAssets. Liquidator receives slightly more collateral than debt repaid."
    WIKI_RECOMMENDATION = "Compute repaidAssets only after the final repaidShares value is settled: `uint256 repaidAssets = repaidShares.toAssetsUp(...)`. Avoid storing intermediates that are later overridden by a more precise calculation."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^liquidate$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^liquidate$'}, {'function.body_contains_regex': 'toSharesDown|toAssetsUp|toAssetsDown'}, {'function.body_contains_regex': 'seizedAssets|repaidShares|repaidAssets'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-morpho-liquidation-rounding-double-conversion: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
