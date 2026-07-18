"""
glider-hash-collision-with-abiencode-packed-and-dynamic-t — generated from reference/patterns.dsl/glider-hash-collision-with-abiencode-packed-and-dynamic-t.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-hash-collision-with-abiencode-packed-and-dynamic-t.yaml
Source: hexens-glider/hash-collision-with-abiencode-packed-and-dynamic-t
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderHashCollisionWithAbiencodePackedAndDynamicT(AbstractDetector):
    ARGUMENT = "glider-hash-collision-with-abiencode-packed-and-dynamic-t"
    HELP = "Hash Collision with abi.encodePacked and Dynamic Types"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-hash-collision-with-abiencode-packed-and-dynamic-t.yaml"
    WIKI_TITLE = "Hash Collision with abi.encodePacked and Dynamic Types"
    WIKI_DESCRIPTION = "Detects dangerous use of abi.encodePacked with multiple dynamic types (strings, bytes, arrays) which can lead to hash collisions."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query hash-collision-with-abiencode-packed-and-dynamic-t. Tags: hash-collision, abi.encodePacked, keccak256, signature."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.calls_function_matching': '^(abi\\.encodePacked|keccak256)$'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-hash-collision-with-abiencode-packed-and-dynamic-t: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
