"""
glider-lack-of-signature-validation-check-against-low-s-v — generated from reference/patterns.dsl/glider-lack-of-signature-validation-check-against-low-s-v.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-lack-of-signature-validation-check-against-low-s-v.yaml
Source: hexens-glider/lack-of-signature-validation-check-against-low-s-v
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderLackOfSignatureValidationCheckAgainstLowSV(AbstractDetector):
    ARGUMENT = "glider-lack-of-signature-validation-check-against-low-s-v"
    HELP = "Lack of signature validation check against low s value"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-lack-of-signature-validation-check-against-low-s-v.yaml"
    WIKI_TITLE = "Lack of signature validation check against low s value"
    WIKI_DESCRIPTION = "This query identifies contracts that use ecrecover for signature verification but fail to check if the signature's 's' value is low (s <= secp256k1n / 2), allowing attackers to use malleable signatures and potentially replay or forge transactions."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query lack-of-signature-validation-check-against-low-s-v. Tags: signature, ecrecover, malleability, SWC-117."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.calls_function_matching': '^(ecrecover)$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-lack-of-signature-validation-check-against-low-s-v: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
