"""
fx-silo-liquidation-rounding-up-missing — generated from reference/patterns.dsl/fx-silo-liquidation-rounding-up-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-silo-liquidation-rounding-up-missing.yaml
Source: github:silo-finance/silo-contracts-v2@3cc2f54
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxSiloLiquidationRoundingUpMissing(AbstractDetector):
    ARGUMENT = "fx-silo-liquidation-rounding-up-missing"
    HELP = "valueToAssetsByRatio() uses plain integer division (floor) when computing assets from a ratio. For partial liquidation with very small positions (e.g., 1 wei collateral), floor rounding returns 0 assets where 1 is correct, making the liquidation compute zero collateral to seize and leaving dust posi"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-silo-liquidation-rounding-up-missing.yaml"
    WIKI_TITLE = "valueToAssetsByRatio uses floor division — dust collateral positions become unliquidatable"
    WIKI_DESCRIPTION = "Liquidation ratio-to-asset conversion functions that compute `value * totalAssets / totalValue` with plain integer division will return 0 for value=1 when totalAssets < totalValue. This creates dust positions with non-zero borrow that cannot be liquidated because the computed seizable collateral is 0, causing permanent bad debt."
    WIKI_EXPLOIT_SCENARIO = "Silo (2024): a position has 1 wei collateral and borrows against it. Partial liquidation computes valueToAssetsByRatio(1, totalAssets, totalValue) → 0 (floor) → no collateral to seize → liquidation reverts or succeeds with zero seizure, leaving permanent bad debt."
    WIKI_RECOMMENDATION = "Use ceiling division for collateral-to-seize calculations: `Math.mulDiv(_value, _totalAssets, _totalValue, Rounding.UP)`. This ensures even 1-wei positions return at least 1 asset to seize."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^valueToAssetsByRatio$|^_valueToAssets'}]
    _MATCH = [{'function.kind': 'internal_or_external_or_public'}, {'function.name_matches': 'valueToAssets|convertToAssets|toAssets'}, {'function.body_contains_regex': '_value\\s*\\*\\s*_totalAssets\\s*/\\s*_totalValue|value\\s*\\*\\s*totalAssets\\s*/\\s*totalValue'}, {'function.body_not_contains_regex': 'mulDiv.*UP|Rounding\\.UP|Math\\.mulDiv.*Rounding'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-silo-liquidation-rounding-up-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
