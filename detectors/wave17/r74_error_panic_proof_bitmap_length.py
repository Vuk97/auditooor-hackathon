"""
r74-error-panic-proof-bitmap-length — generated from reference/patterns.dsl/r74-error-panic-proof-bitmap-length.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-error-panic-proof-bitmap-length.yaml
Source: r74b-cross-firm-tob+cs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74ErrorPanicProofBitmapLength(AbstractDetector):
    ARGUMENT = "r74-error-panic-proof-bitmap-length"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: a Merkle-style verifier iterates a caller-supplied bitmap and indexes `siblings[siblingIndex]` without visible max-length and bitmap/leaf consistency guards, so malformed proofs can trigger Panic(0x32)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-error-panic-proof-bitmap-length.yaml"
    WIKI_TITLE = "Proof verifier missing max-length cap on bitmap/siblings field"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row targets the owned proof-verifier shape where `verifyProof` iterates `bitmap.length`, indexes `siblings[siblingIndex]` from set bits, and omits visible guards such as `bitmap.length <= MAX_BITMAP_BYTES`, `siblings.length <= MAX_DEPTH`, and `leafKeys.length <= bitmap.length * 8`. That omission leaves malformed proofs able to walk off the end of `siblin"
    WIKI_EXPLOIT_SCENARIO = "A bridge-style sparse Merkle verifier accepts `verifyProof(leafKeys, bitmap, siblings)`. The attacker sends a bitmap with many set bits but only a few sibling hashes. Because the verifier never caps `bitmap.length` or `siblings.length`, the nested loop keeps incrementing `siblingIndex` until `siblings[siblingIndex]` reads past the end of the array and panics, cheaply DoS-ing relayed or batched ver"
    WIKI_RECOMMENDATION = "Require `bitmap.length > 0`, `bitmap.length <= MAX_BITMAP_BYTES`, `siblings.length <= MAX_DEPTH`, and `leafKeys.length <= bitmap.length * 8` before iterating. Keep submission_posture NOT_SUBMIT_READY until coverage extends beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(proof|Proof|merkle|Merkle|bitmap|siblings|leafKeys|SMT|SparseM|verify)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(verify|_verify|verifyProof|validateProof|checkProof)'}, {'function.body_contains_regex': '(?is)bitmap\\.length'}, {'function.body_contains_regex': '(?is)siblings\\s*\\[\\s*\\w+'}, {'function.body_contains_regex': '(?is)leafKeys\\.length|bitmap\\.length\\s*\\*\\s*8'}, {'function.body_contains_regex': '(?is)(for|while)\\s*\\([^)]*(bitmap\\.length|leafKeys\\.length)'}, {'function.body_not_contains_regex': '(?is)MAX_(?:BITMAP|DEPTH|SIBLINGS)|require\\s*\\(\\s*bitmap\\.length\\s*>\\s*0|require\\s*\\(\\s*bitmap\\.length\\s*<=\\s*\\w+|require\\s*\\(\\s*siblings\\.length\\s*<=\\s*\\w+|require\\s*\\(\\s*leafKeys\\.length\\s*<=\\s*bitmap\\.length\\s*\\*\\s*8'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-error-panic-proof-bitmap-length: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
