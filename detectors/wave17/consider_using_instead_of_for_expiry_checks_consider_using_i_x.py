"""
consider-using-instead-of-for-expiry-checks-consider-using-i-x — generated from reference/patterns.dsl/consider-using-instead-of-for-expiry-checks-consider-using-i-x.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py consider-using-instead-of-for-expiry-checks-consider-using-i-x.yaml
Source: code4arena audit 2024-08-phi
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConsiderUsingInsteadOfForExpiryChecksConsiderUsingIX(AbstractDetector):
    ARGUMENT = "consider-using-instead-of-for-expiry-checks-consider-using-i-x"
    HELP = "[L-09] Consider using < instead of <= for expiry checks Consider using < instead of <= on Line 625 below. From the frontend, we might just want the signature to be valid for the current block. So we just use block.timestamp but currently it requires expiresIn to be greater than block.timestamp . Fro"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/consider-using-instead-of-for-expiry-checks-consider-using-i-x.yaml"
    WIKI_TITLE = "Consider using < instead of <= for expiry checks\n"
    WIKI_DESCRIPTION = "[L-09] Consider using < instead of <= for expiry checks Consider using < instead of <= on Line 625 below. From the frontend, we might just want the signature to be valid for the current block. So we just use block.timestamp but currently it requires expiresIn to be greater than block.timestamp . From the frontend, we might just want the signature to be valid for the current block. So we just use b"
    WIKI_EXPLOIT_SCENARIO = "Per audit finding: [L-09] Consider using < instead of <= for expiry checks Consider using < instead of <= on Line 625 below. From the frontend, we might just want the signature to be valid for the current block. So we just use block.timestamp but currently it requires expiresIn to be greater than block.timestamp . From the frontend, we might just want the signature to be valid for the current bloc"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = []
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': 'expiresIn'}, {'function.not_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.is_mutating': True}, {'function.body_not_contains_regex': 'require\\s*\\('}]

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
                info = [f, f" — consider-using-instead-of-for-expiry-checks-consider-using-i-x: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
