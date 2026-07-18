"""
glider-layer-zero-token-transfers-are-configured-causing — generated from reference/patterns.dsl/glider-layer-zero-token-transfers-are-configured-causing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-layer-zero-token-transfers-are-configured-causing.yaml
Source: hexens-glider/layer-zero-token-transfers-are-configured-causing
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderLayerZeroTokenTransfersAreConfiguredCausing(AbstractDetector):
    ARGUMENT = "glider-layer-zero-token-transfers-are-configured-causing"
    HELP = "LayerZero send with identical amountLD/minAmountLD (decimalConversionRate slippage)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-layer-zero-token-transfers-are-configured-causing.yaml"
    WIKI_TITLE = "LayerZero send with identical amountLD/minAmountLD (decimalConversionRate slippage)"
    WIKI_DESCRIPTION = "Flags LayerZero/OFT sends where minAmountLD tracks amountLD (or a single var) without considering decimalConversionRate/removeDust, causing SlippageExceeded when dust is removed."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query layer-zero-token-transfers-are-configured-causing. Tags: layerzero, oft, slippage, minAmountLD, removeDust."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'function.kind': 'external_or_public'}, {'function.kind': 'external'}]
    _MATCH = [{'function.calls_function_matching': '^(send|sendoft|sendoftv2)$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-layer-zero-token-transfers-are-configured-causing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
