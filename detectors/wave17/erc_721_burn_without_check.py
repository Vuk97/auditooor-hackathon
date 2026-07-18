"""
erc-721-burn-without-check — generated from reference/patterns.dsl/erc-721-burn-without-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc-721-burn-without-check.yaml
Source: Hexens/Glider-erc-721-tokens-can-be-burned-by-anyone
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc721BurnWithoutCheck(AbstractDetector):
    ARGUMENT = "erc-721-burn-without-check"
    HELP = "ERC-721 burn without check"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc-721-burn-without-check.yaml"
    WIKI_TITLE = "ERC-721 burn without check"
    WIKI_DESCRIPTION = "Main contracts exposing burn(uint256) that calls _burn(uint256), with no modifiers, and no msg.sender usage in the function body."
    WIKI_EXPLOIT_SCENARIO = "Per Glider query tags [ERC-721, access-control, burn]: Main contracts exposing burn(uint256) that calls _burn(uint256), with no modifiers, and no msg.sender usage in the function body."
    WIKI_RECOMMENDATION = "Apply the guard described by the Glider query; cross-reference the canonical Hexens doc."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '_burn\\s*\\('}, {'function.body_not_contains_regex': 'msg\\.sender'}, {'function.has_modifier': {'includes': [], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — erc-721-burn-without-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
