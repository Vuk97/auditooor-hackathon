"""
glider-missing-slippage-parameters-for-swaps-with-curve-f — generated from reference/patterns.dsl/glider-missing-slippage-parameters-for-swaps-with-curve-f.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-missing-slippage-parameters-for-swaps-with-curve-f.yaml
Source: hexens-glider/missing-slippage-parameters-for-swaps-with-curve-f
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMissingSlippageParametersForSwapsWithCurveF(AbstractDetector):
    ARGUMENT = "glider-missing-slippage-parameters-for-swaps-with-curve-f"
    HELP = "missing-slippage-parameters-for-swaps-with-curve-f"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-missing-slippage-parameters-for-swaps-with-curve-f.yaml"
    WIKI_TITLE = "missing-slippage-parameters-for-swaps-with-curve-f"
    WIKI_DESCRIPTION = "missing-slippage-parameters-for-swaps-with-curve-f"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query missing-slippage-parameters-for-swaps-with-curve-f. Tags: ."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.calls_function_matching': '^(exchange|exchange_underlying|exchange_with_best_rate|exchange_extended|add_liquidity|remove_liquidity|remove_liquidity_one_coin|remove_liquidity_imbalance)$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-missing-slippage-parameters-for-swaps-with-curve-f: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
