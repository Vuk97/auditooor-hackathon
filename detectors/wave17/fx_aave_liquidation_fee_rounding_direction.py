"""
fx-aave-liquidation-fee-rounding-direction — generated from reference/patterns.dsl/fx-aave-liquidation-fee-rounding-direction.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-aave-liquidation-fee-rounding-direction.yaml
Source: github:aave-dao/aave-v3-origin@b6567d4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxAaveLiquidationFeeRoundingDirection(AbstractDetector):
    ARGUMENT = "fx-aave-liquidation-fee-rounding-direction"
    HELP = "Liquidation protocol fee scaling uses rayDivFloor to convert the fee amount to scaled shares, but the corresponding AToken.transferOnLiquidation uses rounding-UP when computing shares. The direction mismatch can leave a 1-wei shortfall, causing the fee transfer to revert in edge cases."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-aave-liquidation-fee-rounding-direction.yaml"
    WIKI_TITLE = "Liquidation protocol fee uses rayDivFloor vs AToken rounding-UP — direction mismatch causes transfer revert"
    WIKI_DESCRIPTION = "When a liquidation protocol fee is collected, the amount must be converted from assets to scaled AToken shares. If the conversion uses floor-rounding (rayDivFloor) but the AToken internally uses ceiling-rounding (rounding UP) for the same conversion, the computed share count may be 1 wei short of what the transfer actually requires, causing the liquidation to revert in a subtle edge case."
    WIKI_EXPLOIT_SCENARIO = "Aave v3 Certora-12 (2024): liquidationProtocolFeeAmount.rayDivFloor(liquidityIndex) under-estimates shares by 1 wei in boundary cases. The AToken.transferOnLiquidation computes shares rounding UP, so the scaled balance check fails by exactly 1 wei, reverting the liquidation."
    WIKI_RECOMMENDATION = "Use rayDivCeil (ceiling division) when converting the fee amount to scaled shares to match the rounding direction used by the AToken transfer: `scaledFee = feeAmount.rayDivCeil(liquidityIndex)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^executeLiquidationCall$|^liquidationCall$'}]
    _MATCH = [{'function.kind': 'internal_or_external_or_public'}, {'function.name_matches': 'liquidat|[Ll]iquidation'}, {'function.body_contains_regex': 'rayDivFloor|rayDiv\\b'}, {'function.body_not_contains_regex': 'rayDivCeil|scaledDown.*Ceil'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-aave-liquidation-fee-rounding-direction: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
