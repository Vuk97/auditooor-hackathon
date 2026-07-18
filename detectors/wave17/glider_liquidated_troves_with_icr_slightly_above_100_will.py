"""
glider-liquidated-troves-with-icr-slightly-above-100-will — generated from reference/patterns.dsl/glider-liquidated-troves-with-icr-slightly-above-100-will.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-liquidated-troves-with-icr-slightly-above-100-will.yaml
Source: hexens-glider/liquidated-troves-with-icr-slightly-above-100-will
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderLiquidatedTrovesWithIcrSlightlyAbove100Will(AbstractDetector):
    ARGUMENT = "glider-liquidated-troves-with-icr-slightly-above-100-will"
    HELP = "StabilityPool liquidations using 100% ICR threshold (gas compensation edge case)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-liquidated-troves-with-icr-slightly-above-100-will.yaml"
    WIKI_TITLE = "StabilityPool liquidations using 100% ICR threshold (gas compensation edge case)"
    WIKI_DESCRIPTION = "Find liquidation logic in Liquity/Trove-like systems where StabilityPool liquidations use a 100% ICR threshold without introducing a 100.5% (or gas compensation buffer), potentially causing losses to StabilityPool depositors."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query liquidated-troves-with-icr-slightly-above-100-will. Tags: liquidation, stability-pool, ICR, gas-compensation, trove."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'function.name_matches': '(liquidate|liquidateTroves|batchLiquidate|liquidatePending|liquidateCDP)'}]
    _MATCH = [{'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-liquidated-troves-with-icr-slightly-above-100-will: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
