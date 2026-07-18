"""
glider-missing-message-origin-validation-in-layer-zero-v2 — generated from reference/patterns.dsl/glider-missing-message-origin-validation-in-layer-zero-v2.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-missing-message-origin-validation-in-layer-zero-v2.yaml
Source: hexens-glider/missing-message-origin-validation-in-layer-zero-v2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMissingMessageOriginValidationInLayerZeroV2(AbstractDetector):
    ARGUMENT = "glider-missing-message-origin-validation-in-layer-zero-v2"
    HELP = "missing-message-origin-validation-in-layer-zero-v2"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-missing-message-origin-validation-in-layer-zero-v2.yaml"
    WIKI_TITLE = "missing-message-origin-validation-in-layer-zero-v2"
    WIKI_DESCRIPTION = "missing-message-origin-validation-in-layer-zero-v2"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query missing-message-origin-validation-in-layer-zero-v2. Tags: ."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'function.name_matches': '^(lzCompose)$'}]
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
                info = [f, f" — glider-missing-message-origin-validation-in-layer-zero-v2: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
